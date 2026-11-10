"""
Solver for Capacity-Constrained Set Covering Problem (CC-SCP)
Implements Algorithm 1: Priority-Queue Max-Heap Backtracking Search
CS6103 Computer and Network Security Project - IIITDM Kancheepuram
Authors: Raghul Vishwa (CS23I1025) and Amit Sharma (CS23B1093)
"""

import heapq
from typing import Dict, List, Set, Tuple, Optional
from src.attack_graph import AttackGraph


class CCSCPSolver:
    """
    Solves the optimal IDS Rule Placement problem under sensor capacity constraints.
    Minimizes total deployed rule instances sum_{i} |rho(d_i)| while guaranteeing:
    1. Complete coverage of all vulnerabilities in the attack graph V
    2. Capacity headroom constraint: for each sensor d_i,
       (|rho(d_i)|) * (mu_i + lambda * sigma_i) <= C_i
    """

    def __init__(self, attack_graph: AttackGraph, lambda_headroom: float = 2.5):
        self.ag = attack_graph
        self.lambda_headroom = lambda_headroom
        self.best_solution: Optional[Dict[str, Set[str]]] = None
        self.best_cost = float("inf")
        self.nodes_explored = 0
        self.pruned_branches = 0

    def compute_sensor_load(self, sensor_id: str, rule_count: int) -> float:
        """
        Computes effective traffic processing load with statistical burst headroom:
        Load = rule_count * (mu_i + lambda * sigma_i)
        """
        sensor = self.ag.sensors[sensor_id]
        burst_rate = sensor.mean_rate + self.lambda_headroom * sensor.std_rate
        return rule_count * burst_rate

    def is_capacity_feasible(self, sensor_id: str, current_rules: Set[str], new_rule: str) -> bool:
        """
        Evaluates whether adding new_rule to sensor_id violates headroom constraint:
        Load <= C_i
        """
        sensor = self.ag.sensors[sensor_id]
        projected_count = len(current_rules) + (0 if new_rule in current_rules else 1)
        load = self.compute_sensor_load(sensor_id, projected_count)
        return load <= sensor.capacity_pps

    def solve_max_heap_backtracking(self) -> Dict[str, Set[str]]:
        """
        Algorithm 1: Priority-Queue Backtracking Search with Max-Heap Ordering
        """
        all_vulns = set(self.ag.vulnerabilities.keys())
        initial_assignment = {s_id: set() for s_id in self.ag.sensors.keys()}
        self.best_solution = None
        self.best_cost = float("inf")
        self.nodes_explored = 0
        self.pruned_branches = 0

        self._backtrack(
            covered_vulns=set(),
            current_assignment=initial_assignment,
            all_vulns=all_vulns
        )

        if self.best_solution is None:
            raise RuntimeError("CC-SCP Infeasible: No placement can satisfy full attack graph coverage within capacity!")

        return self.best_solution

    def _backtrack(
        self,
        covered_vulns: Set[str],
        current_assignment: Dict[str, Set[str]],
        all_vulns: Set[str]
    ):
        self.nodes_explored += 1
        current_cost = sum(len(rules) for rules in current_assignment.values())

        # Pruning 1: Branch and bound by cost
        if current_cost >= self.best_cost:
            self.pruned_branches += 1
            return

        # Base case: All vulnerabilities are covered
        if covered_vulns == all_vulns:
            self.best_cost = current_cost
            self.best_solution = {k: set(v) for k, v in current_assignment.items()}
            return

        uncovered = all_vulns - covered_vulns

        # Max-Heap for candidate selection:
        # Priority Key: (-delta_coverage, -remaining_headroom, sensor_id, rule_id)
        # Python heapq is a min-heap, so negate values for Max-Heap behavior
        pq = []
        for s_id, sensor in self.ag.sensors.items():
            for r_id in self.ag.rules.keys():
                if r_id in current_assignment[s_id]:
                    continue

                rule_coverage = self.ag.get_coverage(s_id, r_id)
                delta_v = rule_coverage & uncovered

                if not delta_v:
                    continue

                if not self.is_capacity_feasible(s_id, current_assignment[s_id], r_id):
                    self.pruned_branches += 1
                    continue

                current_load = self.compute_sensor_load(s_id, len(current_assignment[s_id]) + 1)
                headroom = sensor.capacity_pps - current_load

                # Insert into Max-Heap
                heapq.heappush(pq, (-len(delta_v), -headroom, s_id, r_id, delta_v))

        # Explore candidates in order of priority
        while pq:
            neg_delta, neg_headroom, s_id, r_id, delta_v = heapq.heappop(pq)

            # Recalculate feasibility (in case assignment state updated)
            if not self.is_capacity_feasible(s_id, current_assignment[s_id], r_id):
                continue

            current_assignment[s_id].add(r_id)
            new_covered = covered_vulns | delta_v

            self._backtrack(new_covered, current_assignment, all_vulns)

            # Backtrack
            current_assignment[s_id].remove(r_id)

    def solve_uniform_baseline(self) -> Dict[str, Set[str]]:
        """
        Conventional Security Baseline: Deploy all catalog rules onto all sensors.
        """
        all_rules = set(self.ag.rules.keys())
        return {s_id: set(all_rules) for s_id in self.ag.sensors.keys()}

    def solve_greedy_set_cover(self) -> Dict[str, Set[str]]:
        """
        Standard Greedy Set Cover: Selects maximum coverage without capacity awareness.
        """
        all_vulns = set(self.ag.vulnerabilities.keys())
        covered = set()
        assignment = {s_id: set() for s_id in self.ag.sensors.keys()}

        while covered != all_vulns:
            best_candidate = None
            best_gain = 0
            for s_id in self.ag.sensors.keys():
                for r_id in self.ag.rules.keys():
                    if r_id in assignment[s_id]:
                        continue
                    gain = len((self.ag.get_coverage(s_id, r_id) - covered))
                    if gain > best_gain:
                        best_gain = gain
                        best_candidate = (s_id, r_id)

            if best_candidate is None:
                break

            s_id, r_id = best_candidate
            assignment[s_id].add(r_id)
            covered |= self.ag.get_coverage(s_id, r_id)

        return assignment
