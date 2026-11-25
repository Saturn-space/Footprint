"""
Unit Tests for Intelligence Graph Representation (W4 Phase 6)
Tests graph construction, topological traversal, connected components,
isolated nodes, and JSON serialization.
"""

import unittest

from src.correlation.intelligence_graph import IntelligenceGraph
from src.schema import Asset, AssetRelationship


class TestIntelligenceGraph(unittest.TestCase):

    def setUp(self):
        self.graph = IntelligenceGraph()
        self.a_domain = Asset(
            asset_id="ASSET:DOMAIN:example.com",
            asset_type="domain",
            canonical_value="example.com",
            display_name="example.com"
        )
        self.a_ip = Asset(
            asset_id="ASSET:IPV4:93.184.216.34",
            asset_type="ipv4",
            canonical_value="93.184.216.34",
            display_name="93.184.216.34"
        )
        self.a_lab = Asset(
            asset_id="ASSET:IPV4:192.168.56.111",
            asset_type="ipv4",
            canonical_value="192.168.56.111",
            display_name="192.168.56.111 (LAB)",
            tags=["lab"]
        )
        self.a_port = Asset(
            asset_id="ASSET:PORT:tcp:22",
            asset_type="port",
            canonical_value="tcp:22",
            display_name="Port 22/TCP"
        )

    def test_add_nodes_and_edges(self):
        """Verifies adding nodes and edges creates graph connections."""
        self.graph.add_node(self.a_domain)
        self.graph.add_node(self.a_ip)

        rel = AssetRelationship(
            relationship_id="REL-1",
            source_asset_id=self.a_domain.asset_id,
            target_asset_id=self.a_ip.asset_id,
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            evidence_ids=["EVID-1"],
            confidence="DIRECT",
            confidence_score=0.85,
            confidence_explanation="Direct DNS"
        )
        self.graph.add_edge(rel)

        neighbors = self.graph.get_neighbors(self.a_domain.asset_id)
        self.assertEqual(neighbors, [self.a_ip.asset_id])

    def test_duplicate_edge_prevention(self):
        """Verifies duplicate edges between same nodes and predicate are deduplicated."""
        self.graph.add_node(self.a_domain)
        self.graph.add_node(self.a_ip)

        rel1 = AssetRelationship(
            relationship_id="REL-1",
            source_asset_id=self.a_domain.asset_id,
            target_asset_id=self.a_ip.asset_id,
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            evidence_ids=["EVID-1"],
            confidence="DIRECT",
            confidence_score=0.85,
            confidence_explanation="Direct DNS"
        )
        rel2 = AssetRelationship(
            relationship_id="REL-1",
            source_asset_id=self.a_domain.asset_id,
            target_asset_id=self.a_ip.asset_id,
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            evidence_ids=["EVID-1", "EVID-2"],
            confidence="CORROBORATED",
            confidence_score=0.95,
            confidence_explanation="Corroborated"
        )
        self.graph.add_edge(rel1)
        self.graph.add_edge(rel2)

        self.assertEqual(len(self.graph.edges), 1)

    def test_isolated_node_detection(self):
        """Verifies isolated nodes with zero degree are correctly identified."""
        self.graph.add_node(self.a_domain)
        self.graph.add_node(self.a_ip)
        self.graph.add_node(self.a_lab)  # Isolated

        rel = AssetRelationship(
            relationship_id="REL-1",
            source_asset_id=self.a_domain.asset_id,
            target_asset_id=self.a_ip.asset_id,
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            evidence_ids=["EVID-1"],
            confidence="DIRECT",
            confidence_score=0.85,
            confidence_explanation="Direct DNS"
        )
        self.graph.add_edge(rel)

        isolated = self.graph.get_isolated_nodes()
        self.assertEqual(isolated, [self.a_lab.asset_id])

    def test_disconnected_components_analysis(self):
        """Verifies two separate clusters (e.g. Public vs Lab) form separate connected components."""
        # Component 1: example.com -> 93.184.216.34
        self.graph.add_node(self.a_domain)
        self.graph.add_node(self.a_ip)
        self.graph.add_edge(AssetRelationship(
            relationship_id="REL-1",
            source_asset_id=self.a_domain.asset_id,
            target_asset_id=self.a_ip.asset_id,
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            evidence_ids=["EVID-1"],
            confidence="DIRECT",
            confidence_score=0.85,
            confidence_explanation="DNS"
        ))

        # Component 2: 192.168.56.111 -> tcp:22
        self.graph.add_node(self.a_lab)
        self.graph.add_node(self.a_port)
        self.graph.add_edge(AssetRelationship(
            relationship_id="REL-2",
            source_asset_id=self.a_lab.asset_id,
            target_asset_id=self.a_port.asset_id,
            relationship_type="IP_HAS_OPEN_PORT",
            evidence_ids=["EVID-2"],
            confidence="DIRECT",
            confidence_score=0.85,
            confidence_explanation="Nmap"
        ))

        comps = self.graph.get_connected_components()
        self.assertEqual(len(comps), 2)
        # Check both components have size 2
        self.assertEqual(len(comps[0]), 2)
        self.assertEqual(len(comps[1]), 2)

    def test_json_serialization(self):
        """Verifies to_dict produces valid dictionary with nodes, edges, and metrics."""
        self.graph.add_node(self.a_domain)
        d = self.graph.to_dict()
        self.assertIn("metrics", d)
        self.assertIn("nodes", d)
        self.assertIn("edges", d)
        self.assertIn("components", d)
        self.assertEqual(d["metrics"]["node_count"], 1)
        self.assertEqual(d["metrics"]["edge_count"], 0)


if __name__ == "__main__":
    unittest.main()

