# Optimizing IDS Rule Placement via Set Covering with Capacity Constraints

**Course Project — CS6103: Computer and Network Security**  
**Department of Computer Science and Engineering, IIITDM Kancheepuram**

### Team Members
- **Raghul Vishwa** (`CS23I1025`)
- **Amit Sharma** (`CS23B1093`)

---

## About The Project

In enterprise networks, security engineers often enable every available signature rule across all deployed Intrusion Detection Systems (IDS like Snort or Suricata). The assumption is that more rules everywhere = better security. 

However, in practice, this causes what we call the **Rule Overload Paradox**:
- Pattern matching against hundreds or thousands of PCRE/string rules consumes heavy CPU cycles.
- When high-volume traffic bursts or DDoS surges hit, the sensor's packet processing capacity gets maxed out.
- The OS kernel buffer (`AF_PACKET` socket ring buffer) overflows and starts silently dropping packets without inspecting them.
- Attackers exploit this exact window: by flooding the network with background traffic, their exploit payload slips right through the dropped packets undetected.

In this project, we modeled rule deployment as a **Capacity-Constrained Set Covering Problem (CC-SCP)**. Instead of blindly putting every rule on every sensor, we analyze the multi-hop attack graph and distribute complementary subsets of rules across sensors so that:
1. **100% of attack paths remain covered** (every exploit sequence is intercepted somewhere along its path).
2. **Each sensor stays within its traffic headroom** (`mean_rate + lambda * std_dev <= Capacity`), completely eliminating packet drop blind spots.

This work reproduces, tests, and extends the formulation introduced by **Ghosh et al. (Computers & Security, Elsevier 2025/2026)**.

---

## What's in this Repository

```text
├── src/
│   ├── attack_graph.py    # Enterprise topology (4 sensors, 4 hosts, CVE exploit mapping)
│   ├── solver.py          # Algorithm 1: Max-Heap Priority Backtracking search + baselines
│   ├── simulator.py       # Traffic burst & socket queue overflow simulator (CSE-CIC-IDS2017)
│   └── evaluate.py        # Benchmark pipeline reproducing Table I & Table II results
├── tests/
│   └── test_solver.py     # Unit tests verifying coverage invariants and capacity constraints
├── paper/
│   ├── main.tex           # Full LaTeX paper source (IEEE conference format)
│   ├── references.bib     # Citations (12 papers including original Ghosh et al. DOI)
│   ├── IEEEtran.cls       # IEEE format class file
│   └── images/            # High-res figures (system architecture, attack paths, drop plots)
├── docs/
│   └── IDS_Rule_Placement_Final_Paper.pdf  # Final compiled 7-page report
├── requirements.txt       # Python dependencies
└── README.md
```

---

## How It Works (Algorithm 1)

Our solver uses a **Priority-Queue Backtracking Search with a Max-Heap**:
- At each step, it checks which vulnerability is still uncovered on the attack paths.
- It computes a priority key for each candidate `(sensor, rule)` pair:
  $$\text{Key} = (\text{New Vulnerabilities Covered}, \text{Remaining Sensor Headroom})$$
- It prioritizes pairs that cover the most uncovered exploits while leaving the largest safety headroom on the sensor.
- Any branch that would exceed the physical capacity headroom (`load > C_i`) is pruned immediately, which avoids exponential search time and runs in $\mathcal{O}(|D||R|\log(|D||R|))$.

---

## How to Run

### 1. Setup
Make sure you have Python 3.8+ installed. Install the dependencies:
```bash
pip install -r requirements.txt
```

### 2. Run the Evaluation Benchmark
To solve the placement problem and simulate normal, brute-force, and DDoS traffic bursts:
```bash
python3 src/evaluate.py
```

This will print the full comparative tables:
- Total rule instances across sensors (Uniform vs Greedy vs CC-SCP).
- Packet drop rates across traffic scenarios.
- Missed exploit packets per sensor.

### 3. Run the Unit Tests
To verify that coverage and capacity constraints hold strictly:
```bash
python3 -m unittest discover -s tests
```

---

## Key Results Summary

We simulated this across the CSE-CIC-IDS2017 traffic distributions on a 4-sensor enterprise testbed:

| Metric | Uniform Deployment (Default) | Our CC-SCP Placement |
|---|:---:|:---:|
| **Total Rule Instances Deployed** | 32 rules | **4 rules** (87.5% reduction) |
| **Normal Traffic Drop Rate** | 27.7% | **0.0%** |
| **Brute-Force Traffic Drop Rate** | 30.6% | **0.0%** |
| **Volumetric DDoS Drop Rate** | Up to 59.5% | **0.4%** |
| **Missed Exploit Packets (Bypassed)** | 691 packets | **0 packets (100% intercepted)** |

---

## Reference Paper

- Arka Ghosh, Domenico Ditale, Massimiliano Albanese, and Preetam Mukherjee. *"Optimizing the placement of intrusion detection rules in enterprise networks."* **Computers & Security**, Elsevier, 2025/2026.  
  DOI: [10.1016/j.cose.2025.104748](https://doi.org/10.1016/j.cose.2025.104748)
