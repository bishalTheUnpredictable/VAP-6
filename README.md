# 🛡️VAP-6: A Benchmarking Framework on Vulnerability Assessment and Penetration Testing for Language Models

This project benchmarks popular open-source large language models (LLMs) using curated datasets based on **CVE**, **CWE**, **CVSS**, **CEH**, **PenTest+**, and **VAPT tools**. The evaluation includes both **automatic answer generation** and **performance comparison** using ground truth answers.

---

## 🧠 Models Used (via Ollama)

We use the following models, available via [Ollama](https://ollama.com/):

| Model Nickname | Model ID (Ollama)   | Size | Approx. Time (varies based on system resources) |
|----------------|----------------------|------|-----------------------------|
| `gemma2`       | `gemma2:2b`          | 2B   | ~2:01 hours                  |
| `llama3.2`     | `llama3.2:3b`        | 3B   | ~1:59 hours                  |
| `qwen2.5`      | `qwen2.5:3b`         | 3B   | ~1:54 hours                  |

---

## 🧩 Project Structure

```

VAP-6/
├── datasets/                # Input MCQ datasets
├── ground\_truth/            # Ground truth answers for scoring
├── results/                 # Auto-generated answers by models
├── evaluation\_results/      # Summarized metrics (accuracy, etc.)
├── main.py                  # Benchmarking script
├── evaluation.py            # Evaluation script
└── README.md                # You're here!

````

---

## 📚 Dataset Overview

| Dataset Name (Paper)      | File Name (datasets/)               | Description                                           |
|---------------------------|--------------------------------------|-------------------------------------------------------|
| **CVE-MCQs**              | 1.cvemcqs.txt                        | Multiple choice questions about known CVEs            |
| **CWE-MCQs**              | 2.cwemcqs.txt                        | Questions related to Common Weakness Enumerations     |
| **CVSS-MCQs**             | 3.cvss.txt                           | Questions on the CVSS scoring system                  |
| **CEH-1 / CEH-2 / CEH-3** | CEH_v12_Practice_Exam_1/2/3.txt      | Certified Ethical Hacker v12 practice sets            |
| **CVE2Metasploit**        | cvetometasploit.txt                  | Links CVEs to Metasploit modules                      |
| **PenTest-1 to 5**        | PenTest_PTO002_Practice_Exam1-5.txt | CompTIA PenTest+ PTO-002 exam questions               |
| **VAPT-Tools**            | vaptTools.txt                        | Questions on VAPT tools like Burp Suite, Nessus, etc. |

Each of these has a corresponding `_Answers.txt` file inside `ground_truth/`.

---

## 💻 Setup Instructions (Windows)

### 1. 🧰 Install Python (if not already)

- Download from: https://www.python.org/downloads/windows/
- Recommended: Python 3.10+
- Make sure to check “Add Python to PATH” during installation.

---

### 2. 🐳 Install Ollama (LLM Backend)

Ollama allows you to run open-source models locally.

- Download from: https://ollama.com/download
- Run the installer and open a terminal (Command Prompt or PowerShell)

---

### 3. 📦 Pull Required Models

Use the following commands to download the models:

```bash
ollama pull gemma2:2b
ollama pull llama3.2:3b
ollama pull qwen2.5:3b
````

This may take a few minutes based on your internet connection and disk space.

---

### 4. 📁 Clone or Download this Repo

```bash
git clone <your-repo-url>
cd VAP-6
```

Or manually download and extract it.

---

## ▶️ Running the Benchmark

### Step 1: Generate LLM Outputs

This script runs all datasets across all 3 models.

```bash
python main.py
```

📝 This will generate outputs in the `results/<model_name>/` folders.

---

### Step 2: Evaluate Model Accuracy

Once the model answers are saved, run:

```bash
python evaluation.py
```

This script compares model outputs with ground truth and generates:

* `evaluation_results/comprehensive_results.txt` – Line-by-line breakdown
* `evaluation_results/evaluation_summary.txt` – Final accuracy summary
* `evaluation_results/<model>_detailed_results.txt` – Per-model insights

---


Detailed logs and incorrectly answered questions are available in the respective files.

---

## 📞 Support

If you face issues setting up Ollama, check their [FAQs](https://ollama.com/library) or contact the maintainer.

---


## ✅ TODO (Optional Extensions)

* Add more open-source LLMs to the benchmark
* Extend datasets with new vulnerability corpora
* Visualize results in a dashboard
