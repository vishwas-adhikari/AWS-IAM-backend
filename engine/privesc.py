"""
Privilege-escalation edges and attack-path search.

graph_builder draws who can *assume* which role. This module adds the other
ways an identity can turn its IAM permissions into more access, as edges:

  CAN_SELF_ESCALATE  principal -> Account Admin   grant itself admin rights
  CAN_TAKE_OVER      principal -> user            obtain that user's credentials
  CAN_MODIFY_TRUST   principal -> role            rewrite the role's trust policy to let itself in
  CAN_PASS_ROLE      principal -> role            launch compute that runs as the role

Then, for every non-admin starting point, it finds the shortest chain of
edges (CAN_ASSUME included) that ends at admin.

Scope matches policy_engine: identity policies only. SCPs, permission
boundaries, resource-based policies and most Conditions are not evaluated,
so a path means "allowed by identity policy" and should be confirmed manually.

Known false positives (by design, documented in the README):
  - CreateLoginProfile only works if the target has no console password yet,
    UpdateLoginProfile only if it has one; both are flagged regardless.
  - EC2 PassRole really needs an instance profile wrapping the role.
Known stricter-than-AWS rule:
  - Lambda PassRole requires lambda:InvokeFunction, although a function can
    also be run through an event source mapping.
"""
import networkx as nx

from engine.iam_normalize import get_trust_principal_entries

ADMIN_NODE_TYPE = "ADMIN"

# Edges that represent something the source can actually do.
# TRUSTS (account root -> role) only delegates to IAM, so it is not traversable.
ATTACK_EDGES = {"CAN_ASSUME", "CAN_SELF_ESCALATE", "CAN_TAKE_OVER", "CAN_MODIFY_TRUST", "CAN_PASS_ROLE"}

# Node types an attacker can start from
START_TYPES = {"USER", "ROLE", "PUBLIC", "EXTERNAL_ACCOUNT"}

# Grant yourself admin by writing a policy onto your own identity
SELF_POLICY_ACTIONS = {
    "user": ["iam:AttachUserPolicy", "iam:PutUserPolicy"],
    "role": ["iam:AttachRolePolicy", "iam:PutRolePolicy"],
}
# Same idea through a group the user is already in
GROUP_POLICY_ACTIONS = ["iam:AttachGroupPolicy", "iam:PutGroupPolicy"]

# Get working credentials for another user
TAKEOVER_ACTIONS = ["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"]

# Service a role must trust -> actions needed to run code as that role
PASSROLE_SERVICES = {
    "lambda.amazonaws.com": ["lambda:CreateFunction", "lambda:InvokeFunction"],
    "ec2.amazonaws.com": ["ec2:RunInstances"],
}


def admin_node_id(account_id):
    return f"admin:{account_id}"


def _is_aws_managed(policy_arn):
    # AWS-managed policies can't be edited by customers, so CreatePolicyVersion can't touch them
    return ":iam::aws:policy/" in policy_arn


def _group_arn(group, account_id):
    return group.get("Arn") or f"arn:aws:iam::{account_id}:group/{group['GroupName']}"


class PrivescAnalyzer:
    def __init__(self, graph, engine, data):
        """
        graph:  a built graph_builder.IAMGraph (edges are added to it in place)
        engine: policy_engine.PolicyEngine for the same data
        data:   the dict from aws_wrapper.fetch_account_data()
        """
        self.graph = graph
        self.engine = engine
        self.account_id = data["account_id"]
        self.users = data.get("users", [])
        self.roles = data.get("roles", [])
        self.groups = {g["GroupName"]: g for g in data.get("groups", [])}
        self.admin_id = admin_node_id(self.account_id)

        principals = [engine.get(u) for u in self.users] + [engine.get(r) for r in self.roles]
        self.admin_arns = {p.arn for p in principals if engine.is_admin(p)}
        self.non_admins = [p for p in principals if p.arn not in self.admin_arns]

    # --- edge discovery ---

    def add_escalation_edges(self):
        """Adds every escalation edge to the graph. Admins are skipped: they need no escalation."""
        for p in self.non_admins:
            self._self_escalation(p)
            self._user_takeover(p)
            self._trust_rewrite(p)
            self._pass_role(p)

    def _escalate_to_admin(self, p, technique):
        self.graph.add_node(self.admin_id, label="Account Admin", type=ADMIN_NODE_TYPE, risk="CRITICAL")
        self.graph.add_edge(p.arn, self.admin_id, label="CAN_SELF_ESCALATE", technique=technique)

    def _self_escalation(self, p):
        allows = self.engine.allows

        # 1. Attach AdministratorAccess (or write an inline *:* policy) onto itself
        for action in SELF_POLICY_ACTIONS[p.kind]:
            if allows(p, action, p.arn):
                self._escalate_to_admin(p, action)

        # 2. Publish a new default version of a customer-managed policy it already has
        for policy_arn in p.attached_policy_arns:
            if not _is_aws_managed(policy_arn) and allows(p, "iam:CreatePolicyVersion", policy_arn):
                self._escalate_to_admin(p, "iam:CreatePolicyVersion")
                break

        if p.kind != "user":
            return

        # 3. Join a group that already has admin
        for name, group in self.groups.items():
            group_principal = self.engine.group_principals.get(name)
            if (group_principal and self.engine.is_admin(group_principal)
                    and allows(p, "iam:AddUserToGroup", _group_arn(group, self.account_id))):
                self._escalate_to_admin(p, f"iam:AddUserToGroup ({name})")

        # 4. Write admin onto a group it is already a member of
        user = next((u for u in self.users if u.get("Arn") == p.arn), {})
        for name in user.get("GroupList", []):
            group = self.groups.get(name)
            if not group:
                continue
            for action in GROUP_POLICY_ACTIONS:
                if allows(p, action, _group_arn(group, self.account_id)):
                    self._escalate_to_admin(p, f"{action} ({name})")

    def _user_takeover(self, p):
        for user in self.users:
            target = self.engine.get(user)
            if target.arn == p.arn:
                continue  # new keys for yourself grant nothing new
            for action in TAKEOVER_ACTIONS:
                if self.engine.allows(p, action, target.arn):
                    self.graph.add_edge(p.arn, target.arn, label="CAN_TAKE_OVER", technique=action)

    def _trust_rewrite(self, p):
        for role in self.roles:
            target = self.engine.get(role)
            if target.arn != p.arn and self.engine.allows(p, "iam:UpdateAssumeRolePolicy", target.arn):
                # Same account: a trust policy naming p is enough on its own, so p can then assume it
                self.graph.add_edge(p.arn, target.arn, label="CAN_MODIFY_TRUST",
                                    technique="iam:UpdateAssumeRolePolicy")

    def _pass_role(self, p):
        for role in self.roles:
            target = self.engine.get(role)
            if target.arn == p.arn or not self.engine.allows(p, "iam:PassRole", target.arn):
                continue
            services = {v for t, v in get_trust_principal_entries(role.get("AssumeRolePolicyDocument"))
                        if t == "Service"}
            for service, actions in PASSROLE_SERVICES.items():
                if service in services and all(self.engine.allows_on_any_resource(p, a) for a in actions):
                    self.graph.add_edge(p.arn, target.arn, label="CAN_PASS_ROLE",
                                        technique=" + ".join(["iam:PassRole"] + actions))

    # --- path search ---

    def _attack_graph(self):
        g = nx.DiGraph()
        g.add_nodes_from(self.graph.graph.nodes)
        for u, v, data in self.graph.graph.edges(data=True):
            if any(label in ATTACK_EDGES for label, _ in data.get("relations", [])):
                g.add_edge(u, v)
        return g

    def _hop(self, u, v):
        nodes = self.graph.graph.nodes
        relations = [r for r in self.graph.graph.edges[u, v]["relations"] if r[0] in ATTACK_EDGES]
        return {
            "from": u,
            "to": v,
            "from_label": nodes[u].get("label", u),
            "to_label": nodes[v].get("label", v),
            "edge": relations[0][0],
            "techniques": sorted({t for _, t in relations if t}),
        }

    def find_paths(self):
        """
        Shortest path from each non-admin starting node to admin.
        Returns [{"source", "source_label", "target", "hops": [...]}], one per source.
        """
        g = self._attack_graph()
        targets = self.admin_arns | {self.admin_id}
        nodes = self.graph.graph.nodes
        results = []

        for source in sorted(g.nodes):
            if source in targets or nodes[source].get("type") not in START_TYPES:
                continue
            reachable = nx.single_source_shortest_path(g, source)
            hits = [t for t in targets if t in reachable]
            if not hits:
                continue
            target = min(hits, key=lambda t: (len(reachable[t]), t))
            path = reachable[target]
            results.append({
                "source": source,
                "source_label": nodes[source].get("label", source),
                "target": target,
                "hops": [self._hop(u, v) for u, v in zip(path, path[1:])],
            })
        return results


def analyze(graph, engine, data):
    """Adds escalation edges to `graph` and returns the paths to admin."""
    analyzer = PrivescAnalyzer(graph, engine, data)
    analyzer.add_escalation_edges()
    return analyzer.find_paths()


def describe(path):
    """'Intern-Dave -> Maintenance-Role [CAN_ASSUME]' for the finding text."""
    parts = [path["source_label"]]
    for hop in path["hops"]:
        how = ", ".join(hop["techniques"]) or hop["edge"]
        parts.append(f"{hop['to_label']} [{how}]")
    return " -> ".join(parts)