"""
Traffic Surge and Packet Drop Simulation Engine
Evaluates Snort buffer overflow, packet drops, and exploit detection fidelity
CS6103 Computer and Network Security Project - IIITDM Kancheepuram
Authors: Raghul Vishwa (CS23I1025) and Amit Sharma (CS23B1093)
"""

import numpy as np
from dataclasses import dataclass
from typing import Dict, Set, List
from src.attack_graph import AttackGraph


@dataclass
class SimulationResult:
    sensor_id: str
    total_packets: int
    processed_packets: int
    dropped_packets: int
    drop_rate_pct: float
    cpu_utilization_pct: float
    exploit_packets_seen: int
    exploit_packets_missed: int


class NetworkTrafficSimulator:
    """
    Simulates high-speed packet processing queues across IDS sensors under
    empirical traffic distributions derived from CSE-CIC-IDS2017.
    """

    def __init__(self, attack_graph: AttackGraph, seed: int = 42):
        self.ag = attack_graph
        np.random.seed(seed)

    def run_sensor_simulation(
        self,
        sensor_id: str,
        deployed_rules: Set[str],
        traffic_mode: str = "normal",
        sim_duration_sec: int = 100,
        exploit_volume: int = 1000
    ) -> SimulationResult:
        sensor = self.ag.sensors[sensor_id]
        rule_count = len(deployed_rules)

        # Baseline per-rule CPU evaluation cost factor
        # Each active signature in Snort adds Aho-Corasick state transitions and PCRE checks
        rule_cost_factor = 1.0 + (rule_count * 0.18)

        # Traffic parameters by mode
        if traffic_mode == "normal":
            mean_rate = sensor.mean_rate
            std_rate = sensor.std_rate
            burst_multiplier = 1.0
        elif traffic_mode == "bruteforce":
            # Brute-force generates high SYN packet arrival frequency
            mean_rate = sensor.mean_rate * 1.45
            std_rate = sensor.std_rate * 1.80
            burst_multiplier = 1.35
        elif traffic_mode == "ddos":
            # Volumetric DDoS flooding
            mean_rate = sensor.mean_rate * 2.10
            std_rate = sensor.std_rate * 2.60
            burst_multiplier = 1.85
        else:
            raise ValueError(f"Unknown traffic mode: {traffic_mode}")

        # Simulate 1-second interval arrivals over sim_duration_sec
        arrivals = np.random.normal(mean_rate, std_rate, sim_duration_sec)
        arrivals = np.clip(arrivals, a_min=1000.0, a_max=None)

        # Total incoming packets
        total_packets = int(np.sum(arrivals))

        # Sensor physical processing capacity per second
        effective_capacity = sensor.capacity_pps / rule_cost_factor

        processed = 0
        dropped = 0

        # Queue buffer size (e.g. Linux AF_PACKET socket ring buffer)
        ring_buffer_size = 8000
        current_queue = 0

        for rate in arrivals:
            current_queue += rate
            service_capacity = effective_capacity
            
            if current_queue > service_capacity:
                processed_this_sec = service_capacity
                current_queue -= service_capacity
                if current_queue > ring_buffer_size:
                    dropped_this_sec = current_queue - ring_buffer_size
                    current_queue = ring_buffer_size
                else:
                    dropped_this_sec = 0
            else:
                processed_this_sec = current_queue
                dropped_this_sec = 0
                current_queue = 0

            processed += processed_this_sec
            dropped += dropped_this_sec

        drop_rate = (dropped / total_packets) * 100.0 if total_packets > 0 else 0.0
        avg_load = (mean_rate * rule_cost_factor) / sensor.capacity_pps * 100.0
        cpu_util = min(100.0, avg_load)

        # Exploit inspection:
        # Exploit packets that arrive during dropped intervals escape inspection
        exploit_missed = int(exploit_volume * (drop_rate / 100.0))
        
        # If the sensor has NO rule to detect the exploit, they are not caught
        # But if rule IS deployed, drop_rate determines whether they drop at socket
        return SimulationResult(
            sensor_id=sensor_id,
            total_packets=total_packets,
            processed_packets=int(processed),
            dropped_packets=int(dropped),
            drop_rate_pct=round(drop_rate, 2),
            cpu_utilization_pct=round(cpu_util, 2),
            exploit_packets_seen=exploit_volume,
            exploit_packets_missed=exploit_missed
        )
