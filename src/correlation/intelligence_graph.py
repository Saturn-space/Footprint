"""
OSINT-RECON Intelligence Graph Module
Constructs a topological network graph of correlated reconnaissance assets and relationships.
Provides graph traversal, connected components analysis, and JSON serialization.
"""

from typing import Dict, List, Set, Any, Optional
from collections import defaultdict

from src.schema import Asset, AssetRelationship


class IntelligenceGraph:
    """
    Lightweight, pure-Python directed graph representation of the reconnaissance network.
    Maintains nodes (assets), edges (relationships), and topological properties.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[str, Dict[str, Any]] = {}
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)

    def add_node(self, asset: Asset):
        """Adds or updates a node representing an Asset."""
        self.nodes[asset.asset_id] = {
            "id": asset.asset_id,
            "type": asset.asset_type,
            "label": asset.display_name,
            "canonical_value": asset.canonical_value,
            "tags": list(asset.tags),
            "sources": list(asset.sources),
            "attributes": dict(asset.attributes)
        }
        # Ensure adjacency entry exists even if isolated
        if asset.asset_id not in self.adjacency:
            self.adjacency[asset.asset_id] = set()

    def add_edge(self, relationship: AssetRelationship):
        """Adds a directed edge representing an AssetRelationship."""
        edge_key = f"{relationship.source_asset_id}->{relationship.relationship_type}->{relationship.target_asset_id}"

        # Ensure both nodes exist; if missing, create placeholder entries
        if relationship.source_asset_id not in self.nodes:
            self.nodes[relationship.source_asset_id] = {
                "id": relationship.source_asset_id,
                "type": "unknown",
                "label": relationship.source_asset_id,
                "tags": [],
                "sources": [],
                "attributes": {}
            }
        if relationship.target_asset_id not in self.nodes:
            self.nodes[relationship.target_asset_id] = {
                "id": relationship.target_asset_id,
                "type": "unknown",
                "label": relationship.target_asset_id,
                "tags": [],
                "sources": [],
                "attributes": {}
            }

        self.edges[edge_key] = {
            "id": relationship.relationship_id,
            "source": relationship.source_asset_id,
            "target": relationship.target_asset_id,
            "relationship_type": relationship.relationship_type,
            "confidence": relationship.confidence,
            "confidence_score": relationship.confidence_score,
            "confidence_explanation": relationship.confidence_explanation,
            "evidence_ids": list(relationship.evidence_ids),
            "first_observed": relationship.first_observed,
            "last_observed": relationship.last_observed
        }

        self.adjacency[relationship.source_asset_id].add(relationship.target_asset_id)
        self.reverse_adjacency[relationship.target_asset_id].add(relationship.source_asset_id)

    def build_from(self, assets: List[Asset], relationships: List[AssetRelationship]):
        """Populates the graph from lists of Asset and AssetRelationship instances."""
        for a in assets:
            self.add_node(a)
        for r in relationships:
            self.add_edge(r)

    def get_neighbors(self, asset_id: str) -> List[str]:
        """Returns outgoing neighbors of a node."""
        return sorted(list(self.adjacency.get(asset_id, set())))

    def get_isolated_nodes(self) -> List[str]:
        """Returns IDs of nodes with zero incoming and zero outgoing edges."""
        isolated = []
        for node_id in self.nodes:
            out_degree = len(self.adjacency.get(node_id, set()))
            in_degree = len(self.reverse_adjacency.get(node_id, set()))
            if out_degree == 0 and in_degree == 0:
                isolated.append(node_id)
        return sorted(isolated)

    def get_connected_components(self) -> List[List[str]]:
        """
        Calculates weakly connected components (treating edges as undirected).
        Returns list of component node lists sorted by component size (largest first).
        """
        visited: Set[str] = set()
        components: List[List[str]] = []

        # Undirected adjacency for component discovery
        undirected: Dict[str, Set[str]] = defaultdict(set)
        for node_id in self.nodes:
            undirected[node_id] = set()
        for src, tgts in self.adjacency.items():
            for tgt in tgts:
                undirected[src].add(tgt)
                undirected[tgt].add(src)

        for node_id in sorted(self.nodes.keys()):
            if node_id not in visited:
                comp: List[str] = []
                queue = [node_id]
                visited.add(node_id)
                while queue:
                    curr = queue.pop(0)
                    comp.append(curr)
                    for neighbor in sorted(undirected[curr]):
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                components.append(sorted(comp))

        return sorted(components, key=lambda c: len(c), reverse=True)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the graph into a standard JSON-compatible node/edge structure."""
        nodes_list = sorted(list(self.nodes.values()), key=lambda n: n["id"])
        edges_list = sorted(list(self.edges.values()), key=lambda e: (e["source"], e["target"]))
        components = self.get_connected_components()
        isolated = self.get_isolated_nodes()

        density = 0.0
        n_count = len(nodes_list)
        e_count = len(edges_list)
        if n_count > 1:
            density = round(e_count / (n_count * (n_count - 1)), 4)

        return {
            "metrics": {
                "node_count": n_count,
                "edge_count": e_count,
                "isolated_node_count": len(isolated),
                "connected_component_count": len(components),
                "graph_density": density
            },
            "nodes": nodes_list,
            "edges": edges_list,
            "components": components,
            "isolated_nodes": isolated
        }

