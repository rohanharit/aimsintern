<div align="center">

# 🛡️ AegisFlow

### LLM Jailbreak Defense & Benchmarking Framework

*Research Internship Project — AIMS (AI & ML Systems)*

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Model](https://img.shields.io/badge/Model-Llama--3.2--3B--Instruct-FF6B35?style=flat&logo=meta)](https://huggingface.co/meta-llama/Llama-3.2-3B-Instruct)
[![Focus](https://img.shields.io/badge/Focus-AI%20Safety-red?style=flat)](#)
[![License](https://img.shields.io/badge/License-Research%20Use-lightgrey?style=flat)](#)

</div>

---

## 📖 What is AegisFlow?

**AegisFlow** is a research-grade framework for **defending Large Language Models against adversarial jailbreak attacks**, with a core focus on **Crescendo** — a state-of-the-art multi-turn jailbreaking technique.

Most safety evaluations only study *how* models fail. AegisFlow goes further:  
it **replicates the attack**, **builds layered defenses**, and **benchmarks how well those defenses hold** — giving a complete picture of LLM robustness under real adversarial pressure.

> Built on `meta-llama/Llama-3.2-3B-Instruct` as the target model.

---

## 🧠 Background: What is the Crescendo Attack?

The **Crescendo attack** (Russinovich et al., USENIX Security 2025) is a multi-turn jailbreak that exploits an LLM's tendency to **follow conversational patterns** and **attend to recently generated context**.

Unlike single-shot DAN-style jailbreaks, Crescendo is subtle and gradual:

```
Turn 1  →  Innocent, abstract question on a sensitive topic
Turn 2  →  Slightly more specific follow-up, still benign-sounding
Turn 3  →  Leverages the model's own prior output to push further
Turn N  →  Model has been slowly guided to produce harmful content
```

Because each individual turn *appears* harmless, traditional single-turn safety filters **fail to catch it**. This is what makes it uniquely dangerous — and what AegisFlow is built to defend against.

---

## 🎯 Project Objectives

| Goal | Description |
|------|-------------|
| 🔴 **Attack Simulation** | Replicate Crescendo-style multi-turn adversarial attacks on Llama-3.2-3B-Instruct |
| 🟢 **Defense Pipeline** | Build a modular guardrail system that intercepts escalating attack patterns |
| 📊 **Benchmarking** | Measure and score defense effectiveness with reproducible metrics |
| 📄 **Reporting** | Generate structured research reports for academic and internship documentation |

---

## 🗂️ Repository Structure

```
aimsintern/
│
├── src/
│   └── aegisflow/              # Core package — all defense & attack logic lives here
│
├── configs/                    # YAML configuration files
│   ├── model_config.yaml       #   → model loading params, tokenizer settings
│   ├── attack_config.yaml      #   → attack tactics, turn limits, escalation thresholds
│   └── defense_config.yaml     #   → guardrail settings, classifier thresholds
│
├── data/                       # Prompt datasets & test cases
│   ├── attack_prompts/         #   → Crescendo seed prompts per harm category
│   └── benign_prompts/         #   → Clean control prompts for false-positive testing
│
├── docs/                       # Research documentation
│   ├── methodology.md          #   → Detailed attack & defense methodology
│   ├── crescendo_analysis.md   #   → Deep dive on Crescendo attack mechanics
│   └── defense_strategies.md   #   → Layered defense design decisions
│
├── reports/                    # Auto-generated analysis reports (per run)
│
├── results/                    # Raw benchmark outputs, JSON evaluation scores
│
├── tests/                      # Unit & integration test suite
│   ├── test_defender.py
│   ├── test_attacker.py
│   └── test_evaluator.py
│
└── README.md
```

---

## ⚙️ Core Modules (`src/aegisflow/`)

### 🔴 Attacker — Crescendo Simulation Engine

Simulates the full Crescendo attack pipeline against the target model.

**What it does:**
- Generates a multi-turn conversation plan targeting a specified harm goal
- Dynamically adapts each follow-up prompt based on the model's prior response
- Detects when the model has been successfully jailbroken (using a judge classifier)
- Records full attack transcripts, turn count, and success/failure outcome

**Key parameters (via `configs/attack_config.yaml`):**
```yaml
tactic: crescendo
max_turns: 10
harm_categories: [violence, weapons, misinformation, illegal_activity]
dynamic_adaptation: true     # modify prompts if model refuses mid-attack
```

---

### 🟢 Defender — AegisFlow Guard Pipeline

A **multi-layer defense system** that intercepts attacks before the model responds.

**Layer 1 — Input Classifier**  
Each incoming user message is scored for adversarial intent. A lightweight classifier checks for escalation signals, topic drift toward harm, and manipulation patterns.

**Layer 2 — Conversation History Monitor**  
Tracks the full conversation context. Flags if the dialogue is following a known Crescendo pattern — even if each individual message seems benign.

**Layer 3 — Dynamic System Prompt Injection**  
When suspicious escalation is detected, injects a safety-reinforcing system prompt mid-conversation to re-anchor the model's behavior.

**Layer 4 — Output Filter**  
Post-generation check on the model's response. If the output crosses defined harm thresholds, it is blocked and replaced with a safe fallback.

**Key parameters (via `configs/defense_config.yaml`):**
```yaml
input_classifier_threshold: 0.72
history_window: 5            # turns to analyze for escalation pattern
output_filter_threshold: 0.85
safe_fallback: "I'm sorry, I can't help with that."
```

---

### 📊 Evaluator — Benchmark & Scoring Framework

Runs systematic evaluations of attack vs. defense and produces structured reports.

**Metrics computed:**

| Metric | Symbol | Description |
|--------|--------|-------------|
| Attack Success Rate | **ASR** | % of attack attempts that successfully extracted harmful content |
| Defense Block Rate | **DBR** | % of attacks successfully blocked by AegisFlow |
| False Positive Rate | **FPR** | % of benign queries incorrectly flagged or blocked |
| Turns to Compromise | **TTC** | Average number of turns before a successful jailbreak |
| Defense Robustness Score | **DRS** | Composite metric: `DBR × (1 - FPR)` |

**Output:** Results are saved to `/results/` as JSON and summarized into human-readable reports in `/reports/`.

---

## 🧪 Tech Stack

| Component | Tool / Library |
|-----------|---------------|
| Target LLM | `meta-llama/Llama-3.2-3B-Instruct` |
| Deep Learning | PyTorch ≥ 2.0 |
| Model Loading | HuggingFace `transformers` ≥ 4.40 |
| Inference | `transformers` pipeline / manual generation loop |
| Config Management | YAML via `PyYAML` |
| Evaluation & Data | `pandas`, `numpy`, `scikit-learn` |
| Language | Python 3.10+ (100%) |

---

## 🚀 Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/rohanharit/aimsintern.git
cd aimsintern
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure your setup
Edit `configs/model_config.yaml` to point to your local Llama model weights or HuggingFace token:
```yaml
model_name: "meta-llama/Llama-3.2-3B-Instruct"
hf_token: "YOUR_HF_TOKEN_HERE"
device: "cuda"   # or "cpu"
```

### 4. Run a benchmark
```bash
# Full attack vs. defense benchmark
python -m aegisflow.evaluator --config configs/default.yaml

# Run only the attack simulation
python -m aegisflow.attacker --tactic crescendo --turns 10 --harm-category weapons

# Run only the defense pipeline (interactive)
python -m aegisflow.defender --interactive
```

### 5. View results
```bash
# Results saved to /results/run_<timestamp>.json
# Reports saved to /reports/report_<timestamp>.md
```

---

## 📈 Key Findings (Summary)

> Full analysis available in `docs/` and `reports/`

- Crescendo attacks achieve high success rates against vanilla `Llama-3.2-3B-Instruct` with no defense, typically compromising the model within **5–8 turns**
- AegisFlow's **Layer 2 (conversation history monitor)** is the most critical defense layer — single-layer input filtering alone is insufficient against Crescendo
- The **DRS (Defense Robustness Score)** drops significantly if the false positive rate is not controlled — aggressive filtering hurts usability
- **Dynamic system prompt injection** (Layer 3) provides measurable improvement when combined with history monitoring

---

## 🔬 Research Context

This project sits at the intersection of **AI Safety**, **Adversarial NLP**, and **LLM Red-Teaming**.

**Related work:**
- [Crescendo: Multi-Turn LLM Jailbreak Attack](https://crescendo-the-multiturn-jailbreak.github.io/) — Russinovich et al., USENIX Security 2025
- [PAIR: Jailbreaking Black Box LLMs in Twenty Queries](https://jailbreaking-llms.github.io/) — Chao et al.
- [Automated Multi-Turn Jailbreaks](https://github.com/AIM-Intelligence/Automated-Multi-Turn-Jailbreaks) — AIM Intelligence
- [X-Teaming: Multi-Turn Jailbreaks and Defenses](https://salmanrahman.net/assets/pdf/multiagent_jailbreaking.pdf)

**Key concepts:** Crescendo, Crescendomation, PAIR, AutoDAN, Constitutional AI, LLM Red-Teaming, Adversarial Prompting, Multi-Turn Safety

---

## 👨‍💻 Author

**Rohan Harit**  
B.Tech Computer Engineering — Delhi Technological University (DTU), Batch 2025–2029  
GSSoC 2026 Contributor | Competitive Programmer | ML/AI Enthusiast


---

## ⚠️ Disclaimer

This project is built **strictly for AI safety research and educational purposes**. The attack simulations are implemented to understand and defend against real-world adversarial techniques — not to cause harm. All experiments are conducted in a controlled research environment.

---

*"The best defense is understanding the attack." — AegisFlow is that understanding.* 🔐
