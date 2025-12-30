import networkx as nx
from engine.iam_normalize import get_trust_principals

class IAMGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_node(self, node_id, label, type, risk="LOW"):
        """Adds a node (User, Role, Policy) to the graph."""
        self.graph.add_node(node_id, label=label, type=type, risk=risk)

    def add_edge(self, source, target, label):
        """Adds a relationship (Can Assume, Attached To)."""
        self.graph.add_edge(source, target, label=label)

    def build_from_data(self, users, roles):
        """
        Parses AWS data and constructs the graph nodes and edges.
        """
        # 1. Add Roles (and check their Trust Policies)
        for role in roles:
            role_name = role.get('RoleName')
            role_arn = role.get('Arn')
            # Add Node
            self.graph.add_node(role_name, type="ROLE", label=role_name, risk="LOW")
            
            # Check Trust Policy (Who can assume this role?)
            trust_doc = role.get('AssumeRolePolicyDocument', {})
            principals = get_trust_principals(trust_doc)
            
            for p in principals:
                # If principal is an ARN in this account, draw an edge
                if isinstance(p, str) and "arn:aws:iam" in p:
                    # Extract name from ARN (simple parsing)
                    source_name = p.split('/')[-1]
                    self.graph.add_edge(source_name, role_name, label="CAN_ASSUME")

        # 2. Add Users
        for user in users:
            user_name = user.get('UserName')
            self.graph.add_node(user_name, type="USER", label=user_name, risk="LOW")
            # (Note: Group membership logic would go here in a full version)

    def get_nodes_and_edges(self):
        """
        Exports graph data in a format ready for the Database/Frontend.
        """
        # Convert NetworkX graph to simple lists
        nodes = []
        for n, data in self.graph.nodes(data=True):
            nodes.append({
                "id": n,
                "label": data.get("label", n),
                "type": data.get("type", "UNKNOWN"),
                "risk": data.get("risk", "LOW")
            })
            
        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "label": data.get("label", "RELATED")
            })
            
        return nodes, edges