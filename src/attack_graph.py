"""
Attack Graph and Network Model for Multi-Sensor IDS Rule Placement.
CS6103 Computer and Network Security Project - IIITDM Kancheepuram
Authors: Raghul Vishwa (CS23I1025) and Amit Sharma (CS23B1093)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


@dataclass
class Vulnerability:
    vuln_id: str
    cve: str
    name: str
    target_host: str
    severity: float  # CVSS score


@dataclass
class Sensor:
    sensor_id: str
    name: str
    capacity_pps: float  # Capacity in packets per second (C_i)
    mean_rate: float     # Mean traffic rate (mu_i)
    std_rate: float      # Traffic standard deviation (sigma_i)
    monitored_hosts: List[str] = field(default_factory=list)


@dataclass
class Rule:
    rule_id: str
    sid: int
    name: str
    detects_vulns: Set[str] = field(default_factory=set)
    cost_weight: float = 1.0


class AttackGraph:
    """
    Represents enterprise multi-hop attack paths and sensor monitoring coverage.
    """
    def __init__(self):
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.sensors: Dict[str, Sensor] = {}
        self.rules: Dict[str, Rule] = {}
        # Mapping: (sensor_id, rule_id) -> Set of covered vulnerability IDs sigma(d_i, r_j)
        self.coverage_map: Dict[Tuple[str, str], Set[str]] = {}
        self.attack_paths: List[List[str]] = []

    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities[vuln.vuln_id] = vuln

    def add_sensor(self, sensor: Sensor):
        self.sensors[sensor.sensor_id] = sensor

    def add_rule(self, rule: Rule):
        self.rules[rule.rule_id] = rule

    def set_coverage(self, sensor_id: str, rule_id: str, covered_vulns: Set[str]):
        self.coverage_map[(sensor_id, rule_id)] = covered_vulns

    def get_coverage(self, sensor_id: str, rule_id: str) -> Set[str]:
        return self.coverage_map.get((sensor_id, rule_id), set())

    @classmethod
    def build_enterprise_topology(cls, capacity_mode: str = "100k", lambda_headroom: float = 2.5) -> "AttackGraph":
        """
        Builds the 4-sensor multi-hop enterprise attack graph matching the paper.
        """
        ag = cls()

        # Define 4 core lateral vulnerabilities
        v1 = Vulnerability("v1", "CVE-2017-0144", "EternalBlue SMBv1 Exploit", "Host 1", 9.8)
        v2 = Vulnerability("v2", "CVE-2017-5638", "Apache Struts2 Content-Type RCE", "Host 2", 10.0)
        v3 = Vulnerability("v3", "CVE-2014-0160", "Heartbleed OpenSSL TLS Leak", "Host 3", 7.5)
        v4 = Vulnerability("v4", "CVE-2019-0708", "BlueKeep Windows RDP Exploit", "Host 4", 9.8)

        for v in [v1, v2, v3, v4]:
            ag.add_vulnerability(v)

        # Baseline per-sensor capacity
        c_val = 100000.0 if capacity_mode == "100k" else 400000.0

        # 4 sensors deployed at ingress, distribution, core, and host-zone boundaries
        # Traffic parameters (mu and sigma) derived from CSE-CIC-IDS2017 benchmark
        s1 = Sensor("d1", "Perimeter IDS (d1)", c_val, mean_rate=22000.0, std_rate=4500.0, monitored_hosts=["Host 1"])
        s2 = Sensor("d2", "DMZ Distribution IDS (d2)", c_val, mean_rate=31000.0, std_rate=6200.0, monitored_hosts=["Host 1", "Host 2"])
        s3 = Sensor("d3", "Internal Core IDS (d3)", c_val, mean_rate=34000.0, std_rate=7100.0, monitored_hosts=["Host 2", "Host 3"])
        s4 = Sensor("d4", "Critical Server IDS (d4)", c_val, mean_rate=28000.0, std_rate=5800.0, monitored_hosts=["Host 3", "Host 4"])

        for s in [s1, s2, s3, s4]:
            ag.add_sensor(s)

        # Attack paths
        # Path 1: Ingress -> Host 1 -> Host 2 -> Host 3 -> Host 4
        ag.attack_paths = [
            ["v1", "v2", "v3", "v4"]
        ]

        # Snort Detection Rules
        r1 = Rule("r1", 2001, "ET EXPLOIT SMB MS17-010 EternalBlue", detects_vulns={"v1"})
        r2 = Rule("r2", 2002, "ET EXPLOIT Apache Struts2 OGNL Injection", detects_vulns={"v2"})
        r3 = Rule("r3", 2003, "ET EXPLOIT OpenSSL Heartbleed Heartbeat Information Leak", detects_vulns={"v3"})
        r4 = Rule("r4", 2004, "ET EXPLOIT Microsoft Remote Desktop BlueKeep Pre-Auth", detects_vulns={"v4"})
        
        # Additional background enterprise signatures
        r5 = Rule("r5", 2005, "ET SCAN Nmap OS Detection Probe", detects_vulns=set())
        r6 = Rule("r6", 2006, "ET POLICY Suspicious Inbound SMB Traffic", detects_vulns=set())
        r7 = Rule("r7", 2007, "ET WEB_SPECIFIC_APPS SQL Injection Probe", detects_vulns=set())
        r8 = Rule("r8", 2008, "ET DOS Inbound SYN Flood Threshold Exceeded", detects_vulns=set())

        for r in [r1, r2, r3, r4, r5, r6, r7, r8]:
            ag.add_rule(r)

        # Mapping coverage: Sensor d_i sees traffic crossing its monitoring boundary
        # Sensor d1 monitors Ingress -> Host 1: can detect v1
        ag.set_coverage("d1", "r1", {"v1"})
        ag.set_coverage("d1", "r5", set())
        ag.set_coverage("d1", "r6", set())

        # Sensor d2 monitors Host 1 <-> Host 2: can detect v1 (lateral) and v2
        ag.set_coverage("d2", "r1", {"v1"})
        ag.set_coverage("d2", "r2", {"v2"})
        ag.set_coverage("d2", "r5", set())

        # Sensor d3 monitors Host 2 <-> Host 3: can detect v2 (lateral) and v3
        ag.set_coverage("d3", "r2", {"v2"})
        ag.set_coverage("d3", "r3", {"v3"})
        ag.set_coverage("d3", "r7", set())

        # Sensor d4 monitors Host 3 <-> Host 4: can detect v3 (lateral) and v4
        ag.set_coverage("d4", "r3", {"v3"})
        ag.set_coverage("d4", "r4", {"v4"})
        ag.set_coverage("d4", "r8", set())

        return ag
