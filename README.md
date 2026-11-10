# Optimizing IDS Rule Placement via Set Covering with Capacity Constraints: A Multi-Sensor Attack Graph Approach

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![IIITDM Kancheepuram](https://img.shields.io/badge/Course-CS6103%20CNS-red.svg)](http://www.iiitdm.ac.in)

This repository contains the simulation testbed, optimization engine, and benchmark evaluation for the **CS6103 Computer and Network Security** course project at **IIITDM Kancheepuram**.

### 👥 Authors
* **Raghul Vishwa** (`CS23I1025`)
* **Amit Sharma** (`CS23B1093`)

*Department of Computer Science and Engineering, Indian Institute of Information Technology, Design and Manufacturing (IIITDM), Kancheepuram, India.*

---

## 📌 Problem Overview & Motivation

Conventional enterprise intrusion detection architectures deploy every signature rule across all network sensors under the assumption that redundancy maximizes threat detection. However, this strategy introduces the **Rule Overload Paradox**:

1. Signature inspection in tools like Snort consumes CPU cycles proportional to the active rule count.
2. During traffic spikes or DDoS surges, sensor CPU processing capacity saturates, filling kernel socket buffers (`AF_PACKET` ring buffer).
3. Packets are dropped silently without inspection, enabling malicious exploits to bypass defenses completely.

We model signature placement as a **Capacity-Constrained Set Covering Problem (CC-SCP)** with statistical headroom constraints ($\mu_i + \lambda \sigma_i \le C_i$). By pruning unnecessary rule redundancies, our solver guarantees 100% exploit coverage across all multi-hop lateral attack paths while eliminating buffer overflow drops (0.0% packet drop rate).

---

## 🔬 Mathematical Formulation

### 1. Attack Graph Coverage
Let $G = (V, E)$ be the enterprise attack graph where $V$ represents system vulnerabilities and $E$ represents exploit transitions across lateral hosts. An assignment $\rho: D \to 2^R$ is valid if and only if:
$$\bigcup_{d_i \in D} \bigcup_{r_j \in \rho(d_i)} \sigma(d_i, r_j) = V$$

### 2. Statistical Headroom Capacity Constraint
To prevent queue saturation during traffic surges without expensive hardware upgrades, each sensor $d_i$ must satisfy:
$$\sum_{r_j \in \rho(d_i)} (\mu_i + \lambda \sigma_i) \le C_i, \quad \forall d_i \in D$$
where $\mu_i$ is empirical mean traffic rate, $\sigma_i$ is traffic standard deviation, and $\lambda$ is the safety headroom multiplier (e.g. $\lambda = 2.5$).

### 3. Algorithm 1: Max-Heap Priority-Queue Backtracking
Candidate sensor-rule pairs $(d_i, r_j)$ are evaluated at each step using composite key:
$$\kappa(d_i, r_j) = \Big( |\sigma(d_i, r_j) \cap V_{\text{uncov}}|, \; C_i - (|\rho(d_i)| + 1)(\mu_i + \lambda\sigma_i) \Big)$$
Assignments offering the highest incremental vulnerability coverage are prioritized; branch-and-bound pruning discards capacity-infeasible branches early.

---

## 📁 Repository Structure

```text
ids-rule-placement-cns/
├── docs/
│   └── IDS_Rule_Placement_Final_Paper.pdf  # Final compiled 7-page IEEE research paper
├── paper/
│   ├── main.tex                           # Full LaTeX conference source
│   ├── references.bib                     # IEEE bibliography with 12 citations
│   ├── IEEEtran.cls                       # IEEE Transactions class file
│   └── images/                            # High-resolution benchmark figures
├── src/
│   ├── attack_graph.py                    # Multi-hop attack graph and topology models
│   ├── solver.py                          # CC-SCP Max-Heap Backtracking solver & baselines
│   ├── simulator.py                       # Packet drop and queue overflow simulator
│   └── evaluate.py                        # Benchmark evaluation pipeline (Table I & II)
├── tests/
│   └── test_solver.py                     # Unittest verification suite
├── requirements.txt                       # Python dependencies
└── README.md
```

---

## 🚀 Quickstart & Reproduction

### 1. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/amitsharma2004/ids-rule-placement-cns.git
cd ids-rule-placement-cns
pip install -r requirements.txt
```

### 2. Run Optimization & Evaluation Pipeline
Reproduce the experimental results comparing Uniform vs CC-SCP placement under CSE-CIC-IDS2017 traffic profiles:
```bash
python3 src/evaluate.py
```

### 3. Run Unit Tests
Verify mathematical invariants and complete attack path coverage:
```bash
python3 -m unittest discover -s tests
```

---

## 📊 Experimental Results

Evaluated on virtual enterprise testbed replaying CSE-CIC-IDS2017 benchmark traces:

| Metric | Uniform Baseline (Full Catalog) | Proposed CC-SCP (Max-Heap Backtracking) |
|---|:---:|:---:|
| **Total Rule Instances** | 32 rules | **4 rules** (87.5% reduction) |
| **Normal Traffic Drop Rate** | 27.7% | **0.0%** |
| **Brute-Force Drop Rate** | 30.6% | **0.0%** |
| **Volumetric DDoS Drop Rate** | Up to 59.5% | **0.4%** |
| **Missed Malicious Packets** | 691 packets | **0 packets (100% caught)** |
| **Search Complexity** | $\mathcal{O}(2^{|D||R|})$ exhaustive | $\mathcal{O}(|D||R|\log(|D||R|))$ |

---

## 📖 Reference & Citation

This project reproduces, evaluates, and extends the foundational work introduced by:

> Arka Ghosh, Domenico Ditale, Massimiliano Albanese, and Preetam Mukherjee, *"Optimizing the placement of intrusion detection rules in enterprise networks,"* **Computers & Security**, Elsevier, 2025/2026.  
> DOI: [10.1016/j.cose.2025.104748](https://doi.org/10.1016/j.cose.2025.104748)

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
