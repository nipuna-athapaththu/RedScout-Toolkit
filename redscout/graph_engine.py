"""Basic attack graph engine using NetworkX."""
import networkx as nx


class AttackGraph:
    def __init__(self):
        self.g = nx.DiGraph()

    def add_host(self, host: str):
        self.g.add_node(host, type="host")

    def add_service(self, host: str, service: str, port: str):
        svc_id = f"{host}:{port}"
        self.g.add_node(svc_id, type="service", service=service, port=port)
        self.g.add_edge(host, svc_id, relation="exposes")

    def add_vulnerability(self, svc_id: str, cve: str, severity: str):
        vuln_id = f"{svc_id}/{cve}"
        self.g.add_node(vuln_id, type="vuln", cve=cve, severity=severity)
        self.g.add_edge(svc_id, vuln_id, relation="has_vuln")

    def summary(self):
        return {
            "hosts": sum(1 for _, d in self.g.nodes(data=True) if d.get("type") == "host"),
            "services": sum(1 for _, d in self.g.nodes(data=True) if d.get("type") == "service"),
            "vulns": sum(1 for _, d in self.g.nodes(data=True) if d.get("type") == "vuln"),
        }

    def export_graphml(self, path: str):
        nx.write_graphml(self.g, path)