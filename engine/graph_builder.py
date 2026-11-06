import re

import networkx as nx
from engine.iam_normalize import get_trust_principal_entries

PUBLIC_NODE_ID = "*"
ACCOUNT_ID_RE = re.compile(r'^\d{12}$')
# arn:partition:service::account:resource
ARN_RE = re.compile(r'^arn:([^:]+):([^:]+):[^:]*:(\d{12}):(.+)$')


class IAMGraph:
    """
    Node IDs are ARNs (or the service / federated provider / "*" string for
    non-IAM principals), so same-named entities in different accounts or of
    different kinds never merge. Labels are the short display names.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.existing_nodes = set()

    def add_node(self, node_id, label, type, risk="LOW"):
        """Adds a node to the graph if it doesn't exist."""
        if node_id not in self.existing_nodes:
            self.graph.add_node(node_id, label=label, type=type, risk=risk)
            self.existing_nodes.add(node_id)

    def add_edge(self, source, target, label, technique=None):
        """
        Adds a relationship. A node pair can hold several relationships
        (e.g. CAN_ASSUME and CAN_PASS_ROLE), kept as a list of (label, technique).
        """
        # Ensure both nodes exist before adding edge to avoid errors
        if source not in self.existing_nodes:
            self.add_node(source, label=source, type="UNKNOWN", risk="LOW")

        if target not in self.existing_nodes:
            self.add_node(target, label=target, type="UNKNOWN", risk="LOW")

        if not self.graph.has_edge(source, target):
            self.graph.add_edge(source, target, relations=[])
        relations = self.graph.edges[source, target]['relations']
        if (label, technique) not in relations:
            relations.append((label, technique))

    def build_from_data(self, users, roles, account_id, engine=None):
        """
        Parses AWS data and constructs the graph nodes and edges.
        `engine` (a policy_engine.PolicyEngine) is used to resolve who can assume
        roles that trust the account root; without it those edges are skipped.
        """
        self.account_id = account_id
        self.engine = engine
        self.local_principals = []  # (node_id, user/role detail)
        self.local_role_ids = {}    # role name -> node_id

        # 1. Add All Local Users First (So we know who exists)
        for user in users:
            node_id = user.get('Arn') or f"arn:aws:iam::{account_id}:user/{user['UserName']}"
            self.add_node(node_id, label=user['UserName'], type="USER", risk="LOW")
            self.local_principals.append((node_id, user))

        # 2. Add Roles
        for role in roles:
            node_id = role.get('Arn') or f"arn:aws:iam::{account_id}:role/{role['RoleName']}"
            self.add_node(node_id, label=role['RoleName'], type="ROLE", risk="LOW")
            self.local_principals.append((node_id, role))
            self.local_role_ids[role['RoleName']] = node_id

        # 3. Analyze Trust Policies (Who can assume each role?)
        for role in roles:
            role_id = self.local_role_ids[role['RoleName']]
            trust_doc = role.get('AssumeRolePolicyDocument', {})
            for principal_type, value in get_trust_principal_entries(trust_doc):
                if principal_type == 'Service':
                    self.add_node(value, label=value, type="SERVICE")
                    self.add_edge(value, role_id, label="CAN_ASSUME")
                elif principal_type == 'Federated':
                    self.add_node(value, label=value.split('/')[-1], type="FEDERATED")
                    self.add_edge(value, role_id, label="CAN_ASSUME")
                else:
                    self._add_aws_trust(value, role_id)

    def _add_aws_trust(self, principal, role_id):
        # Case A: Public Access
        if principal == '*':
            self.add_node(PUBLIC_NODE_ID, label="Anyone (Public)", type="PUBLIC", risk="CRITICAL")
            self.add_edge(PUBLIC_NODE_ID, role_id, label="CAN_ASSUME")
            return

        # A bare account ID means that account's root
        if ACCOUNT_ID_RE.match(principal):
            principal = f"arn:aws:iam::{principal}:root"

        match = ARN_RE.match(principal)
        if not match:
            # e.g. the unique ID AWS leaves behind when a trusted principal is deleted
            self.add_node(principal, label=principal, type="UNKNOWN")
            self.add_edge(principal, role_id, label="CAN_ASSUME")
            return

        service, account, resource = match.group(2), match.group(3), match.group(4)

        # Case B: Another account (its root, or a specific user/role in it)
        if account != self.account_id:
            if resource == 'root':
                label = f"Account {account}"
            else:
                label = f"{resource.split('/')[-1]} ({account})"
            self.add_node(principal, label=label, type="EXTERNAL_ACCOUNT")
            self.add_edge(principal, role_id, label="CAN_ASSUME")
            return

        # Case C: Same-account root - the account delegates to IAM, so only
        # principals whose own policies allow sts:AssumeRole on this role can assume it
        if resource == 'root':
            self.add_node(principal, label="Account Root", type="ACCOUNT_ROOT")
            self.add_edge(principal, role_id, label="TRUSTS")
            if self.engine:
                for source_id, detail in self.local_principals:
                    if source_id != role_id and self.engine.allows(detail, 'sts:AssumeRole', role_id):
                        self.add_edge(source_id, role_id, label="CAN_ASSUME")
            return

        # Case D: Specific same-account user/role - trusted directly
        if service == 'sts' and resource.startswith('assumed-role/'):
            # arn:aws:sts::acct:assumed-role/RoleName/session -> the role itself
            role_name = resource.split('/')[1]
            source_id = self.local_role_ids.get(role_name, principal)
            self.add_node(source_id, label=role_name, type="ROLE")
        else:
            kind = "USER" if resource.startswith('user/') else "ROLE" if resource.startswith('role/') else "UNKNOWN"
            source_id = principal
            self.add_node(source_id, label=resource.split('/')[-1], type=kind)
        self.add_edge(source_id, role_id, label="CAN_ASSUME")

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
            for label, technique in data.get("relations", []):
                edges.append({
                    "source": u,
                    "target": v,
                    "label": f"{label} ({technique})" if technique else label
                })

        return nodes, edges
