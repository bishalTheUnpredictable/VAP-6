import os
import re
import time
import ollama
import subprocess
import threading
from tqdm.auto import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define model configurations
MODELS = {
    "gemma2": "gemma2:2b", # 2:01
    "llama3.2": "llama3.2:3b", # 1:59
    "qwen2.5": "qwen2.5:3b" # 1:54
}

# Define per-file limits
FILE_LIMITS = {
    "1.cvemcqs.txt": 10, # 2000
    "2.cwemcqs.txt": 10, # 2000
    "3.cvss.txt": 10, # 2000
    "CEH_v12_Practice_Exam_1.txt": 125, # 125
    "CEH_v12_Practice_Exam_2.txt": 125, # 125
    "CEH_v12_Practice_Exam_3.txt": 125, # 125
    # "cvetometasploit.txt": 10, # 500
    "PenTest_PTO002_Practice_Exam1.txt": 85, # 85
    "PenTest_PTO002_Practice_Exam2.txt": 10, # 85
    "PenTest_PTO002_Practice_Exam3.txt": 10, # 85
    "PenTest_PTO002_Practice_Exam4.txt": 10, # 85
    "PenTest_PTO002_Practice_Exam5.txt": 10, # 85
    "vaptTools.txt": 500   # Adjust limit as needed
}

# Configuration
RESULTS_DIR = "results"
DATASET_DIR = "datasets"
MAX_WORKERS = 2  # Adjust based on your CPU cores
VRAM_THRESHOLD = 3500  # MB - adjust based on your GPU
VRAM_CHECK_INTERVAL = 5  # seconds
BATCH_SIZE = 3  # Process questions in small batches

# Global state
gpu_available = True
lock = threading.Lock()

def setup_directories():
    """Create necessary directories for storing results."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    for model_name in MODELS.keys():
        model_dir = os.path.join(RESULTS_DIR, model_name)
        os.makedirs(model_dir, exist_ok=True)

def get_gpu_memory():
    """Get GPU memory usage in MB."""
    try:
        result = subprocess.run(['nvidia-smi', '--query-gpu=memory.used', '--format=csv,nounits,noheader'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if result.returncode != 0:
            return None
        used = int(result.stdout.strip())
        return used
    except (subprocess.SubprocessError, ValueError, IndexError):
        return None

def vram_monitor():
    """Monitor VRAM usage and update global GPU availability."""
    global gpu_available
    
    while True:
        used_vram = get_gpu_memory()
        
        with lock:
            if used_vram is not None:
                gpu_available = used_vram < VRAM_THRESHOLD
        
        time.sleep(VRAM_CHECK_INTERVAL)

def generate_answer(model_id, prompt, max_tokens=150, timeout=30, temperature=0.3):
    """Generate answer with automatic device management."""
    global gpu_available
    
    # Check if GPU is available
    with lock:
        current_gpu_available = gpu_available
    
    if not current_gpu_available:
        # If GPU is overloaded, wait briefly before trying
        time.sleep(2)
    
    # Set a timeout to prevent hanging
    start_time = time.time()
    
    try:
        response = ollama.generate(
            model=model_id,
            prompt=prompt,
            options={
                "temperature": temperature,  # Adjustable temperature
                "top_p": 0.9,
                "max_tokens": max_tokens
            }
        )
        return response['response'].strip()
    except Exception as e:
        if time.time() - start_time > timeout:
            return "Error: Request timed out"
        return f"Error: {str(e)}"

def read_questions(file_path):
    """Read questions from a file with a predefined limit."""
    filename = os.path.basename(file_path)
    limit = FILE_LIMITS.get(filename, 1)  # Default to 1 if not in list

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Special parsing for vaptTools.txt
    if filename == "vaptTools.txt":
        questions = re.split(r'\n\d+\.\s+Tool:', content)
        formatted_questions = []
        for i, q in enumerate(questions[1:], 1):  # Skip first empty split
            formatted_q = f"{i}. Tool:{q}".strip()
            formatted_questions.append(formatted_q)
        return formatted_questions[:limit]
        
    # Specific parsing logic for CVSS file
    elif "3.cvss.txt" in filename:
        questions = re.split(r'---\s*\n', content)
        questions = [q.strip() for q in questions if q.strip()]
    else:
        questions = re.split(r'---\s*\n', content)
        if len(questions) <= 1:
            questions = re.split(r'(?:Question\s+\d+:|Q\d+:)', content)
            questions = [q for q in questions if q.strip()]
            if len(questions) <= 1:
                questions = content.split("\n\n")
        
        questions = [q.strip() for q in questions if q.strip()]

    return questions[:limit]

def process_cvss_question(model_id, question, index):
    """Process a single CVSS question with improved prompting based on research."""
    question_text = question.strip()
    
    # Extract the vulnerability description
    question_match = re.search(r'Q\d+:\s+(.*?)(?:\n|$)', question_text)
    vuln_desc = question_match.group(1).strip() if question_match else question_text
    
    # Improved prompt based on research findings
    combined_prompt = f"""Analyze the following vulnerability description and determine the CVSS v3.1 vector.

VULNERABILITY DESCRIPTION:
{vuln_desc}

For each CVSS metric, select the most appropriate value based ONLY on the information provided:

1. Attack Vector (AV): [N=Network, A=Adjacent, L=Local, P=Physical]
2. Attack Complexity (AC): [L=Low, H=High]
3. Privileges Required (PR): [N=None, L=Low, H=High]
4. User Interaction (UI): [N=None, R=Required]
5. Scope (S): [U=Unchanged, C=Changed]
6. Confidentiality Impact (C): [H=High, L=Low, N=None]
7. Integrity Impact (I): [H=High, L=Low, N=None]
8. Availability Impact (A): [H=High, L=Low, N=None]

Provide your answer in this exact format:
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
CVSS Vector: CVSS:3.1/AV:[VALUE]/AC:[VALUE]/PR:[VALUE]/UI:[VALUE]/S:[VALUE]/C:[VALUE]/I:[VALUE]/A:[VALUE]
CVSS Score: [SCORE]

Do not include any explanations, just the formatted answer. If you are uncertain about any metric, analyze the vulnerability description carefully to make the best determination.
"""

    response = generate_answer(model_id, combined_prompt, max_tokens=150)
    
    # Extract information from response
    severity_match = re.search(r'Severity:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    vector_match = re.search(r'CVSS Vector:\s*(CVSS:[^\n]+)', response)
    score_match = re.search(r'CVSS Score:\s*(\d+(\.\d+)?)', response)
    
    # Only use what was actually generated, no defaults
    severity = severity_match.group(1).upper() if severity_match else ""
    vector = vector_match.group(1) if vector_match else ""
    score = score_match.group(1) if score_match else ""
    
    return f"A{index+1}:\nSeverity: {severity}\nCVSS Vector: {vector}\nCVSS Score: {score}\n"

def process_mcq_question(model_id, question, index):
    """Process a single MCQ question."""
    # Extract question number if available
    question_num_match = re.search(r'(?:Question|Q)\s*(\d+):', question)
    question_num = question_num_match.group(1) if question_num_match else str(index+1)
    
    # Improved prompt for MCQ
    prompt = f"""Based on the following multiple-choice question, select the most appropriate answer option (A, B, C, or D).
Provide ONLY the letter of the correct answer without explanation.

{question}

Answer:"""
    
    answer = generate_answer(model_id, prompt, max_tokens=10)
    
    # Extract option letter
    option_match = re.search(r'\b([A-D])\b', answer)
    option = option_match.group(1) if option_match else ""
    
    return f"{question_num}: {option}"

def process_vapt_question(model_id, question, index):
    """Process a penetration testing tool question with specialized prompting."""
    # Extract question number
    question_num_match = re.search(r'^(\d+)\.', question)
    question_num = question_num_match.group(1) if question_num_match else str(index+1)
    
    # Create a specialized prompt for security tool output analysis
    prompt = f"""You are a cybersecurity expert specialized in penetration testing. Analyze this penetration testing scenario carefully:

{question}

Based on your expert analysis of the tool output and scenario, which option (A, B, C, or D) is the most appropriate answer? 
Consider:
1. The specific vulnerabilities or security issues revealed in the tool output
2. Standard penetration testing methodologies and best practices
3. The most logical next step or interpretation given the specific context

Respond with only the letter of your answer (A, B, C, or D). No explanation.
"""
    
    # Generate answer with lower temperature for more deterministic outputs
    answer = generate_answer(model_id, prompt, max_tokens=10, temperature=0.2)
    
    # Extract option letter
    option_match = re.search(r'\b([A-D])\b', answer)
    option = option_match.group(1) if option_match else ""
    
    return f"{question_num}: {option}"

def process_questions_batch(model_id, questions, processor_func, start_idx=0):
    """Process a batch of questions using the specified processor function."""
    results = []
    
    for i, question in enumerate(questions):
        result = processor_func(model_id, question, start_idx + i)
        results.append(result)
    
    return results

def process_file(model_id, file_path, output_path, is_cvss=False, is_vapt=False):
    """Process a file with batched question processing."""
    questions = read_questions(file_path)
    all_results = []
    
    # Select the appropriate processor function
    if is_cvss:
        processor_func = process_cvss_question
    elif is_vapt:
        processor_func = process_vapt_question
    else:
        processor_func = process_mcq_question
    
    # Process questions in batches with progress bar
    with tqdm(total=len(questions), desc=f"Processing {os.path.basename(file_path)}") as pbar:
        for i in range(0, len(questions), BATCH_SIZE):
            batch = questions[i:i+BATCH_SIZE]
            batch_results = process_questions_batch(model_id, batch, processor_func, i)
            all_results.extend(batch_results)
            pbar.update(len(batch))
            
            # Short pause between batches to prevent overloading
            time.sleep(0.5)
    
    # Write results to file
    with open(output_path, 'w', encoding='utf-8') as f:
        if is_cvss:
            f.write("\n---\n".join(all_results))
        else:
            f.write("\n".join(all_results))
    
    print(f"Answers saved to {output_path}")

def process_combined_files(model_id, file_paths, output_path, prefix):
    """Process multiple files and combine answers in one output file."""
    with open(output_path, 'w', encoding='utf-8') as out_file:
        for file_path in tqdm(file_paths, desc=f"Processing {prefix} files"):
            file_name = os.path.basename(file_path)
            questions = read_questions(file_path)
            
            # Write file header
            out_file.write(f"=== Answers from {file_name} ===\n\n")
            
            all_results = []
            
            # Process questions in batches with progress bar
            with tqdm(total=len(questions), desc=f"Processing {file_name}") as pbar:
                for i in range(0, len(questions), BATCH_SIZE):
                    batch = questions[i:i+BATCH_SIZE]
                    batch_results = process_questions_batch(model_id, batch, process_mcq_question, i)
                    all_results.extend(batch_results)
                    pbar.update(len(batch))
                    
                    # Short pause between batches
                    time.sleep(0.5)
            
            out_file.write("\n".join(all_results))
            out_file.write("\n\n")
    
    print(f"{prefix} answers saved to {output_path}")

def main():
    # Setup output directories
    setup_directories()
    
    # Start VRAM monitoring in a separate thread
    monitor_thread = threading.Thread(target=vram_monitor, daemon=True)
    monitor_thread.start()
    
    # Process each model
    for model_name, model_id in tqdm(MODELS.items(), desc="Processing models"):
        print(f"\n{'='*50}\nProcessing model: {model_name}\n{'='*50}")
        
        # Create output directory for this model
        output_dir = os.path.join(RESULTS_DIR, model_name)
        
        # Group files by type
        ceh_files = []
        pentest_files = []
        other_files = []
        
        for file_name in os.listdir(DATASET_DIR):
            file_path = os.path.join(DATASET_DIR, file_name)
            if not os.path.isfile(file_path) or not file_name.endswith('.txt'):
                continue
                
            if file_name.startswith('CEH_'):
                ceh_files.append(file_path)
            elif file_name.startswith('PenTest_'):
                pentest_files.append(file_path)
            else:
                other_files.append((file_name, file_path))
        
        # Process CEH files
        if ceh_files:
            ceh_output = os.path.join(output_dir, f"{model_name}_CEH_answers.txt")
            process_combined_files(model_id, ceh_files, ceh_output, "CEH")
        
        # Process PenTest files
        if pentest_files:
            pentest_output = os.path.join(output_dir, f"{model_name}_PenTest_answers.txt")
            process_combined_files(model_id, pentest_files, pentest_output, "PenTest")
        
        # Process other files
        if other_files:
            for file_name, file_path in tqdm(other_files, desc="Processing other files"):
                output_file = os.path.join(output_dir, f"{model_name}_{file_name}")
                
                if file_name == "3.cvss.txt":
                    process_file(model_id, file_path, output_file, is_cvss=True)
                elif file_name == "vaptTools.txt":
                    process_file(model_id, file_path, output_file, is_vapt=True)
                else:
                    process_file(model_id, file_path, output_file)
        
        print(f"Completed processing for model: {model_name}")

if __name__ == "__main__":
    start_time = time.time()
    main()
    elapsed_time = time.time() - start_time
    print(f"Total execution time: {elapsed_time:.2f} seconds")
