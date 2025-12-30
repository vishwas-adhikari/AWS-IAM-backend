import networkx as nx
from engine.iam_normalize import get_trust_principals

class IAMGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.existing_nodes = set()

    def add_node(self, node_id, label, type, risk="LOW"):
        """Adds a node to the graph if it doesn't exist."""
        if node_id not in self.existing_nodes:
            self.graph.add_node(node_id, label=label, type=type, risk=risk)
            self.existing_nodes.add(node_id)

    def add_edge(self, source, target, label):
        """Adds a relationship."""
        # Ensure both nodes exist before adding edge to avoid errors
        if source not in self.existing_nodes:
            # If source is missing (e.g. external account), create a placeholder
            self.add_node(source, label=source, type="UNKNOWN", risk="LOW")
        
        if target not in self.existing_nodes:
            self.add_node(target, label=target, type="UNKNOWN", risk="LOW")

        self.graph.add_edge(source, target, label=label)

    def build_from_data(self, users, roles):
        """
        Parses AWS data and constructs the graph nodes and edges.
        """
        # 1. Add All Local Users First (So we know who exists)
        for user in users:
            user_name = user.get('UserName')
            self.add_node(user_name, label=user_name, type="USER", risk="LOW")

        # 2. Add Roles and Analyze Trust Policies
        for role in roles:
            role_name = role.get('RoleName')
            self.add_node(role_name, label=role_name, type="ROLE", risk="LOW")
            
            # Check Trust Policy (Who can assume this role?)
            trust_doc = role.get('AssumeRolePolicyDocument', {})
            principals = get_trust_principals(trust_doc)
            
            for p in principals:
                if p == '*':
                    # Case A: Public Access
                    source_id = "The Internet (Public)"
                    self.add_node(source_id, label="The Internet", type="GROUP", risk="CRITICAL")
                    self.add_edge(source_id, role_name, label="CAN_ASSUME")
                
                elif isinstance(p, str) and "arn:aws" in p:
                    # Case B: Specific ARN (User or Role)
                    # p example: "arn:aws:iam::123456789:user/Intern-Dave"
                    
                    # Extract the name part
                    if "/" in p:
                        source_name = p.split('/')[-1] # "Intern-Dave"
                    elif ":" in p:
                        source_name = p.split(':')[-1] # "root" or other
                    else:
                        source_name = p

                    # Add Edge
                    self.add_edge(source_name, role_name, label="CAN_ASSUME")

                elif isinstance(p, str) and "root" in p:
                     # Case C: Account Root Trust
                     # This creates a node for the account root
                     self.add_edge("Account-Root", role_name, label="TRUSTS")

    def get_nodes_and_edges(self):
        """
        Exports graph data in a format ready for the Database/Frontend.
        """
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