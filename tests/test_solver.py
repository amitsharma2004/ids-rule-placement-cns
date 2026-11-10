"""
Unit Tests for CC-SCP Solver and Coverage Invariants
CS6103 Computer and Network Security Project - IIITDM Kancheepuram
Authors: Raghul Vishwa (CS23I1025) and Amit Sharma (CS23B1093)
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.attack_graph import AttackGraph
from src.solver import CCSCPSolver


class TestCCSCPSolver(unittest.TestCase):

    def setUp(self):
        self.ag = AttackGraph.build_enterprise_topology(capacity_mode="100k", lambda_headroom=2.5)
        self.solver = CCSCPSolver(self.ag, lambda_headroom=2.5)

    def test_full_vulnerability_coverage(self):
        """Verify that CC-SCP optimal solution covers 100% of attack graph vulnerabilities."""
        solution = self.solver.solve_max_heap_backtracking()
        covered = set()
        for s_id, rules in solution.items():
            for r_id in rules:
                covered |= self.ag.get_coverage(s_id, r_id)

        all_vulns = set(self.ag.vulnerabilities.keys())
        self.assertEqual(covered, all_vulns, f"Uncovered vulnerabilities: {all_vulns - covered}")

    def test_sensor_capacity_headroom_respected(self):
        """Verify that no sensor violates physical processing capacity."""
        solution = self.solver.solve_max_heap_backtracking()
        for s_id, rules in solution.items():
            load = self.solver.compute_sensor_load(s_id, len(rules))
            capacity = self.ag.sensors[s_id].capacity_pps
            self.assertLessEqual(
                load,
                capacity,
                f"Sensor {s_id} exceeded capacity! Load: {load}, Capacity: {capacity}"
            )

    def test_rule_footprint_reduction(self):
        """Verify that CC-SCP reduces total rule deployments by at least 60% compared to uniform."""
        uniform = self.solver.solve_uniform_baseline()
        optimal = self.solver.solve_max_heap_backtracking()

        u_count = sum(len(r) for r in uniform.values())
        o_count = sum(len(r) for r in optimal.values())

        self.assertLess(o_count, u_count)
        reduction_pct = ((u_count - o_count) / u_count) * 100.0
        self.assertGreaterEqual(reduction_pct, 60.0)


if __name__ == "__main__":
    unittest.main()
