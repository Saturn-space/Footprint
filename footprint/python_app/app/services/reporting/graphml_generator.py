"""Knowledge Graph exporter in GraphML XML format for Gephi, Cytoscape, and Maltego.

Generates standard, well-formed GraphML XML representing persisted cybersecurity investigation
entities, infrastructure hosts, network services, and vulnerability findings without XML injection risks.
"""

from xml.sax.saxutils import escape as xml_escape
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.investigation import InvestigationModel
from app.models.recon import EntityModel
from app.models.scan import ScanFindingHostModel, ScanFindingPortModel
from app.models.vulnerability import VulnerabilityFindingModel


def safe_str(val: Optional[object]) -> str:
    """Escapes special XML characters safely."""
    if val is None:
        return ""
    return xml_escape(str(val))


class GraphMLExporter:
    """Exports persisted investigation entities and relationships to GraphML format."""

    @classmethod
    def generate_graphml(cls, investigation_id: str, db: Session) -> str:
        """Constructs a valid, standard GraphML document from database records."""
        inv = db.get(InvestigationModel, investigation_id)
        if not inv:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        # Query all related records
        entities = db.scalars(
            select(EntityModel).where(EntityModel.investigation_id == investigation_id)
        ).all()

        hosts = db.scalars(
            select(ScanFindingHostModel).where(ScanFindingHostModel.investigation_id == investigation_id)
        ).all()

        ports = db.scalars(
            select(ScanFindingPortModel)
            .join(ScanFindingHostModel, ScanFindingPortModel.host_id == ScanFindingHostModel.id)
            .where(ScanFindingHostModel.investigation_id == investigation_id)
        ).all()

        vulns = db.scalars(
            select(VulnerabilityFindingModel).where(VulnerabilityFindingModel.investigation_id == investigation_id)
        ).all()

        # Build GraphML XML structure
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"',
            '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '         xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">',
            '  <!-- Graph schema attributes -->',
            '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="type" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="details" for="node" attr.name="details" attr.type="string"/>',
            '  <key id="rel" for="edge" attr.name="rel" attr.type="string"/>',
            '  <graph id="G" edgedefault="directed">',
        ]

        # 1. Investigation root node
        inv_node_id = f"inv_{inv.id}"
        inv_label = safe_str(inv.name)
        target_label = inv.active_targets[0] if inv.active_targets else (inv.owned_domains[0] if inv.owned_domains else "N/A")
        inv_details = safe_str(f"Target: {target_label} | Org: {inv.organization_name}")
        lines.append(f'    <node id="{safe_str(inv_node_id)}">')
        lines.append(f'      <data key="label">{inv_label}</data>')
        lines.append('      <data key="type">INVESTIGATION</data>')
        lines.append(f'      <data key="details">{inv_details}</data>')
        lines.append('    </node>')

        # 2. OSINT Entities from passive collection
        for ent in entities:
            ent_node_id = f"entity_{ent.id}"
            lines.append(f'    <node id="{safe_str(ent_node_id)}">')
            lines.append(f'      <data key="label">{safe_str(ent.canonical_value)}</data>')
            lines.append(f'      <data key="type">{safe_str(ent.entity_type)}</data>')
            lines.append(f'      <data key="details">{safe_str(ent.original_value)}</data>')
            lines.append('    </node>')

            # Edge: Investigation -> Entity
            lines.append(f'    <edge source="{safe_str(inv_node_id)}" target="{safe_str(ent_node_id)}">')
            lines.append('      <data key="rel">DISCOVERED_ENTITY</data>')
            lines.append('    </edge>')

        # 3. Active Scan Network Hosts
        host_id_map = {}
        for h in hosts:
            host_node_id = f"host_{h.id}"
            host_id_map[h.id] = host_node_id
            host_label = safe_str(h.address)
            host_details = safe_str(f"Host: {h.hostname or 'unknown'} | Status: {h.status}")
            lines.append(f'    <node id="{safe_str(host_node_id)}">')
            lines.append(f'      <data key="label">{host_label}</data>')
            lines.append('      <data key="type">NETWORK_HOST</data>')
            lines.append(f'      <data key="details">{host_details}</data>')
            lines.append('    </node>')

            # Edge: Investigation -> Host
            lines.append(f'    <edge source="{safe_str(inv_node_id)}" target="{safe_str(host_node_id)}">')
            lines.append('      <data key="rel">RESOLVED_HOST</data>')
            lines.append('    </edge>')

        # 4. Open Ports / Services
        for p in ports:
            port_node_id = f"port_{p.id}"
            port_label = safe_str(f"{p.port_number}/{p.protocol}")
            port_details = safe_str(f"Service: {p.service_name or 'unknown'} | State: {p.state}")
            lines.append(f'    <node id="{safe_str(port_node_id)}">')
            lines.append(f'      <data key="label">{port_label}</data>')
            lines.append('      <data key="type">NETWORK_PORT</data>')
            lines.append(f'      <data key="details">{port_details}</data>')
            lines.append('    </node>')

            # Edge: Host -> Port
            parent_host_node = host_id_map.get(p.host_id, inv_node_id)
            lines.append(f'    <edge source="{safe_str(parent_host_node)}" target="{safe_str(port_node_id)}">')
            lines.append('      <data key="rel">EXPOSES_PORT</data>')
            lines.append('    </edge>')

        # 5. Vulnerability Findings
        for v in vulns:
            vuln_node_id = f"vuln_{v.id}"
            cve_str = v.cve_references[0] if (hasattr(v, 'cve_references') and v.cve_references) else None
            vuln_label = safe_str(cve_str or getattr(v, 'name', None) or "Vulnerability")
            vuln_details = safe_str(f"Severity: {v.severity} | CVSS: {v.cvss_score} | Host: {v.host}")
            lines.append(f'    <node id="{safe_str(vuln_node_id)}">')
            lines.append(f'      <data key="label">{vuln_label}</data>')
            lines.append('      <data key="type">VULNERABILITY</data>')
            lines.append(f'      <data key="details">{vuln_details}</data>')
            lines.append('    </node>')

            # Edge: Root or Host -> Vulnerability
            lines.append(f'    <edge source="{safe_str(inv_node_id)}" target="{safe_str(vuln_node_id)}">')
            lines.append('      <data key="rel">HAS_VULNERABILITY</data>')
            lines.append('    </edge>')

        lines.append('  </graph>')
        lines.append('</graphml>')

        return "\n".join(lines)
