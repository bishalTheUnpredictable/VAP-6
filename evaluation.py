import os
import re
from Levenshtein import distance as levenshtein_distance
from math import sqrt

# Define directories
GROUND_TRUTH_DIR = 'ground_truth/'
RESULTS_DIR = 'results/'
OUTPUT_DIR = 'evaluation_results/'

# Create output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Model directories
MODELS = ['gemma2', 'llama3.2', 'qwen2.5']

# Mapping for MCQ datasets
MCQ_MAPPING = {
    'CVE': ('cveanswers.txt', '1.cvemcqs.txt'),
    'CWE': ('cweanswers.txt', '2.cwemcqs.txt'),
    'PenTest': ('PenTest_answers.txt', 'PenTest_answers.txt'),
    'VAPT Tools': ('vaptTools_answers.txt', 'vaptTools.txt'),
    'CVE→Metasploit': ('cvetometasploitanswers.txt', 'cvetometasploit.txt'),
    'CEH': ('CEH_answers.txt', 'CEH_answers.txt')
}

# CVSS file mapping
CVSS_MAPPING = ('cvssanswers.txt', '3.cvss.txt')

def read_mcq_answers(file_path):
    """Read MCQ answers from file."""
    answers = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Match patterns like "1: A", "1. A", "1 A"
                m = re.match(r'^(\d+)[\.:]?\s*([A-D])$', line, re.IGNORECASE)
                if m:
                    qnum = int(m.group(1))
                    ans = m.group(2).upper()
                    answers[qnum] = ans
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return answers

def read_cvss_data(file_path):
    """Read CVSS data with vector, severity, and score from multiline entries."""
    cvss_data = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            entries = content.split('---')
            for entry in entries:
                lines = entry.strip().splitlines()
                if len(lines) < 4:
                    continue
                entry_id = lines[0].replace(":", "").strip()
                severity = lines[1].split(":", 1)[1].strip().capitalize()
                vector = lines[2].split(":", 1)[1].strip()
                try:
                    score = float(lines[3].split(":", 1)[1].strip())
                except ValueError:
                    score = 0.0
                cvss_data[entry_id] = {
                    'severity': severity,
                    'vector': vector,
                    'score': score
                }
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return cvss_data


def evaluate_mcq_answers():
    """Evaluate MCQ answers for all models and datasets."""
    results = {model: {} for model in MODELS}
    
    for dataset_name, (gt_file, result_pattern) in MCQ_MAPPING.items():
        gt_path = os.path.join(GROUND_TRUTH_DIR, gt_file)
        
        if not os.path.exists(gt_path):
            print(f"Warning: Ground truth file not found: {gt_path}")
            continue
            
        gt_answers = read_mcq_answers(gt_path)
        
        if not gt_answers:
            print(f"Warning: No ground truth answers found for {dataset_name}")
            continue
            
        for model in MODELS:
            result_file = f"{model}_{result_pattern}"
            result_path = os.path.join(RESULTS_DIR, model, result_file)
            
            if not os.path.exists(result_path):
                print(f"Warning: Result file not found: {result_path}")
                continue
                
            model_answers = read_mcq_answers(result_path)
            
            if not model_answers:
                print(f"Warning: No answers found for {model} on {dataset_name}")
                continue
                
            # Count total, correct and incorrect answers
            total = 0
            incorrect = 0
            correct_answers = {}
            incorrect_answers = {}
            
            for qnum, gt_ans in gt_answers.items():
                if qnum in model_answers:
                    total += 1
                    if model_answers[qnum] != gt_ans:
                        incorrect += 1
                        incorrect_answers[qnum] = (gt_ans, model_answers[qnum])
                    else:
                        correct_answers[qnum] = gt_ans
            
            # Calculate accuracy
            accuracy = (total - incorrect) / total * 100 if total > 0 else 0
            
            results[model][dataset_name] = {
                'total': total,
                'correct': total - incorrect,
                'incorrect': incorrect,
                'accuracy': accuracy,
                'correct_answers': correct_answers,
                'incorrect_answers': incorrect_answers
            }
    
    return results

def evaluate_cvss_data():
    """Evaluate CVSS data for all models."""
    results = {model: {} for model in MODELS}
    
    gt_file, result_pattern = CVSS_MAPPING
    gt_path = os.path.join(GROUND_TRUTH_DIR, gt_file)
    
    if not os.path.exists(gt_path):
        print(f"Warning: Ground truth CVSS file not found: {gt_path}")
        return results
        
    gt_data = read_cvss_data(gt_path)
    
    if not gt_data:
        print("Warning: No ground truth CVSS data found")
        return results
        
    for model in MODELS:
        result_file = f"{model}_{result_pattern}"
        result_path = os.path.join(RESULTS_DIR, model, result_file)
        
        if not os.path.exists(result_path):
            print(f"Warning: CVSS result file not found: {result_path}")
            continue
            
        model_data = read_cvss_data(result_path)
        
        if not model_data:
            print(f"Warning: No CVSS data found for {model}")
            continue
            
        # Initialize counters and detailed tracking
        total_entries = len(gt_data)
        severity_mismatches = 0
        severity_details = []
        
        vector_exact_mismatches = 0
        vector_distances = []
        vector_details = []
        
        score_squared_errors = []
        score_details = []
        
        # Evaluate each CVSS entry
        for entry_id, gt_entry in gt_data.items():
            if entry_id in model_data:
                model_entry = model_data[entry_id]
                
                # Check severity (exact match)
                if gt_entry['severity'] != model_entry['severity']:
                    severity_mismatches += 1
                    severity_details.append({
                        'entry': entry_id,
                        'gt': gt_entry['severity'],
                        'pred': model_entry['severity']
                    })
                
                # Check vector (exact match and Levenshtein distance)
                distance = 0
                if gt_entry['vector'] != model_entry['vector']:
                    vector_exact_mismatches += 1
                    distance = levenshtein_distance(gt_entry['vector'], model_entry['vector'])
                    vector_distances.append(distance)
                    vector_details.append({
                        'entry': entry_id,
                        'gt': gt_entry['vector'],
                        'pred': model_entry['vector'],
                        'distance': distance
                    })
                
                # Check score (RMSE)
                squared_error = (gt_entry['score'] - model_entry['score'])**2
                score_squared_errors.append(squared_error)
                score_details.append({
                    'entry': entry_id,
                    'gt': gt_entry['score'],
                    'pred': model_entry['score'],
                    'error': abs(gt_entry['score'] - model_entry['score'])
                })
        
        # Calculate final metrics
        avg_vector_distance = sum(vector_distances) / len(vector_distances) if vector_distances else 0
        rmse_score = sqrt(sum(score_squared_errors) / len(score_squared_errors)) if score_squared_errors else 0
        
        results[model]['CVSS'] = {
            'total': total_entries,
            'severity_mismatches': severity_mismatches,
            'severity_accuracy': ((total_entries - severity_mismatches) / total_entries) * 100 if total_entries > 0 else 0,
            'severity_details': severity_details,
            
            'vector_exact_mismatches': vector_exact_mismatches,
            'vector_exact_accuracy': ((total_entries - vector_exact_mismatches) / total_entries) * 100 if total_entries > 0 else 0,
            'avg_vector_distance': avg_vector_distance,
            'vector_details': vector_details,
            
            'rmse_score': rmse_score,
            'score_details': score_details
        }
    
    return results

def save_results(mcq_results, cvss_results):
    """Save evaluation results to text files."""
    # Create output files
    summary_file = os.path.join(OUTPUT_DIR, 'evaluation_summary.txt')
    comprehensive_file = os.path.join(OUTPUT_DIR, 'comprehensive_results.txt')
    
    with open(summary_file, 'w', encoding='utf-8') as f_sum, \
         open(comprehensive_file, 'w', encoding='utf-8') as f_comp:

        # Write summary headers
        for f in [f_sum, f_comp]:
            f.write("=" * 80 + "\n")
            f.write("MCQ EVALUATION SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            
            # MCQ Table
            f.write(f"{'Model':<12} {'Dataset':<18} {'Total':<8} {'Correct':<10} {'Incorrect':<10} {'Accuracy':<10}\n")
            f.write("-" * 85 + "\n")
            
            for model in MODELS:
                if model in mcq_results:
                    for dataset, metrics in mcq_results[model].items():
                        line = f"{model:<12} {dataset:<18} {metrics['total']:<8} {metrics['correct']:<10} "
                        line += f"{metrics['incorrect']:<10} {metrics['accuracy']:.2f}%\n"
                        f.write(line)
                    f.write("-" * 85 + "\n")

            # CVSS Table
            f.write("\n\n" + "=" * 80 + "\n")
            f.write("CVSS EVALUATION SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"{'Model':<12} {'Severity Acc':<14} {'Vector Exact':<14} {'Avg Lev Dist':<14} {'RMSE':<10}\n")
            f.write("-" * 85 + "\n")
            
            for model in MODELS:
                if model in cvss_results and 'CVSS' in cvss_results[model]:
                    metrics = cvss_results[model]['CVSS']
                    line = f"{model:<12} {metrics['severity_accuracy']:.2f}%{'':<5}"
                    line += f"{metrics['vector_exact_accuracy']:.2f}%{'':<7}"
                    line += f"{metrics['avg_vector_distance']:.2f}{'':<9}"
                    line += f"{metrics['rmse_score']:.4f}\n"
                    f.write(line)
            f.write("-" * 85 + "\n\n")

        # Add comprehensive CVSS details
        f_comp.write("\n\n" + "=" * 80 + "\n")
        f_comp.write("DETAILED CVSS EVALUATION RESULTS\n")
        f_comp.write("=" * 80 + "\n\n")
        
        for model in MODELS:
            if model in cvss_results and 'CVSS' in cvss_results[model]:
                metrics = cvss_results[model]['CVSS']
                
                f_comp.write(f"{model.upper()} MODEL\n{'=' * 40}\n")
                f_comp.write(f"Severity Accuracy: {metrics['severity_accuracy']:.2f}% ")
                f_comp.write(f"(Mismatches: {metrics['severity_mismatches']}/{metrics['total']})\n")
                
                f_comp.write(f"Vector Exact Match: {metrics['vector_exact_accuracy']:.2f}% ")
                f_comp.write(f"(Mismatches: {metrics['vector_exact_mismatches']})\n")
                f_comp.write(f"Average Levenshtein Distance: {metrics['avg_vector_distance']:.2f}\n")
                f_comp.write(f"Score Prediction RMSE: {metrics['rmse_score']:.4f}\n\n")
                
                # Top mismatches
                f_comp.write("Top 5 Severity Mismatches:\n")
                for item in metrics['severity_details'][:5]:
                    f_comp.write(f"  {item['entry']}: GT={item['gt']}, Pred={item['pred']}\n")
                
                f_comp.write("\nTop 5 Vector Mismatches:\n")
                for item in sorted(metrics['vector_details'], key=lambda x: x['distance'], reverse=True)[:5]:
                    f_comp.write(f"  {item['entry']}: Distance={item['distance']}\n")
                    f_comp.write(f"    GT: {item['gt']}\n")
                    f_comp.write(f"    Pred: {item['pred']}\n")
                
                f_comp.write("\nTop 5 Score Deviations:\n")
                for item in sorted(metrics['score_details'], key=lambda x: x['error'], reverse=True)[:5]:
                    f_comp.write(f"  {item['entry']}: Error={item['error']:.2f} ")
                    f_comp.write(f"(GT={item['gt']:.1f}, Pred={item['pred']:.1f})\n")
                
                f_comp.write("\n" + "=" * 60 + "\n\n")

    # Create individual model files
    for model in MODELS:
        model_file = os.path.join(OUTPUT_DIR, f'{model}_detailed_results.txt')
        
        with open(model_file, 'w', encoding='utf-8') as f:
            f.write(f"DETAILED RESULTS FOR {model.upper()}\n")
            f.write("=" * 80 + "\n\n")
            
            # MCQ Results
            if model in mcq_results:
                f.write("MCQ EVALUATION RESULTS\n")
                f.write("-" * 50 + "\n\n")
                for dataset, metrics in mcq_results[model].items():
                    f.write(f"Dataset: {dataset}\n")
                    f.write(f"  Total questions: {metrics['total']}\n")
                    f.write(f"  Correct answers: {metrics['correct']}\n")
                    f.write(f"  Incorrect answers: {metrics['incorrect']}\n")
                    f.write(f"  Accuracy: {metrics['accuracy']:.2f}%\n")
                    
                    if metrics['incorrect'] > 0:
                        f.write("\n  Incorrect Answers:\n")
                        f.write(f"  {'Question':<10} {'Ground Truth':<15} {'Model Answer':<15}\n")
                        f.write("  " + "-" * 40 + "\n")
                        for q, (gt, pred) in metrics['incorrect_answers'].items():
                            f.write(f"  {q:<10} {gt:<15} {pred:<15}\n")
                    f.write("\n" + "-" * 50 + "\n\n")
            
            # CVSS Results
            if model in cvss_results and 'CVSS' in cvss_results[model]:
                f.write("CVSS EVALUATION RESULTS\n")
                f.write("-" * 50 + "\n\n")
                metrics = cvss_results[model]['CVSS']
                f.write(f"Total CVSS entries: {metrics['total']}\n\n")
                
                f.write("Severity Classification:\n")
                f.write(f"  Misclassifications: {metrics['severity_mismatches']} ({metrics['severity_accuracy']:.2f}% accuracy)\n")
                if metrics['severity_mismatches'] > 0:
                    f.write("\n  Top 10 Severity Mismatches:\n")
                    f.write(f"  {'Entry':<10} {'Ground Truth':<10} {'Model Prediction':<18}\n")
                    f.write("  " + "-" * 40 + "\n")
                    for item in metrics['severity_details'][:10]:
                        f.write(f"  {item['entry']:<10} {item['gt']:<10} {item['pred']:<18}\n")
                
                f.write("\nCVSS Vector Analysis:\n")
                f.write(f"  Exact mismatches: {metrics['vector_exact_mismatches']} ({metrics['vector_exact_accuracy']:.2f}% accuracy)\n")
                f.write(f"  Average Levenshtein distance: {metrics['avg_vector_distance']:.2f}\n")
                if metrics['vector_exact_mismatches'] > 0:
                    f.write("\n  Top 10 Vectors by Distance:\n")
                    sorted_vectors = sorted(metrics['vector_details'], key=lambda x: x['distance'], reverse=True)[:10]
                    for item in sorted_vectors:
                        f.write(f"  Entry: {item['entry']}, Distance: {item['distance']}\n")
                        f.write(f"    GT:   {item['gt']}\n")
                        f.write(f"    Pred: {item['pred']}\n\n")
                
                f.write("\nCVSS Score Analysis:\n")
                f.write(f"  RMSE: {metrics['rmse_score']:.4f}\n")
                f.write("\n  Top 10 Score Deviations:\n")
                sorted_scores = sorted(metrics['score_details'], key=lambda x: x['error'], reverse=True)[:10]
                for item in sorted_scores:
                    f.write(f"  Entry: {item['entry']}, Error: {item['error']:.2f}\n")
                    f.write(f"    GT: {item['gt']:.1f}, Pred: {item['pred']:.1f}\n\n")
    
    print(f"Results saved to {OUTPUT_DIR}")

def main():
    # Evaluate MCQ answers
    print("Evaluating MCQ answers...")
    mcq_results = evaluate_mcq_answers()
    
    # Evaluate CVSS data
    print("Evaluating CVSS data...")
    cvss_results = evaluate_cvss_data()
    
    # Save results to files
    print("Saving results...")
    save_results(mcq_results, cvss_results)
    
    print("Evaluation complete!")

if __name__ == "__main__":
    main()