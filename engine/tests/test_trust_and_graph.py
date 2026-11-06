import unittest

from engine.graph_builder import IAMGraph
from engine.iam_normalize import get_trust_principal_entries, get_trust_principals
from engine.policy_engine import PolicyEngine
from engine.tests.helpers import ACCOUNT, ADMIN_ARN, account_data, allow, deny, doc, role, trust, user

OTHER = '222222222222'
ROOT_ARN = f"arn:aws:iam::{ACCOUNT}:root"


def arn(kind, name, account=ACCOUNT):
    return f"arn:aws:iam::{account}:{kind}/{name}"


class TrustPrincipalTests(unittest.TestCase):
    def test_plain_string_star(self):
        self.assertEqual(get_trust_principal_entries(trust("*")), [('AWS', '*')])
        self.assertIn('*', get_trust_principals(trust("*")))

    def test_aws_star(self):
        self.assertEqual(get_trust_principals(trust({"AWS": "*"})), ['*'])

    def test_all_types_strings_and_lists(self):
        policy = trust({
            "AWS": [arn("user", "a"), OTHER],
            "Service": "lambda.amazonaws.com",
            "Federated": ["accounts.google.com"],
        })
        self.assertEqual(sorted(get_trust_principal_entries(policy)), sorted([
            ('AWS', arn("user", "a")), ('AWS', OTHER),
            ('Service', 'lambda.amazonaws.com'), ('Federated', 'accounts.google.com'),
        ]))

    def test_deny_statements_ignored(self):
        policy = doc({"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"})
        self.assertEqual(get_trust_principals(policy), [])

    def test_string_document(self):
        self.assertEqual(get_trust_principals('{"Statement": {"Effect": "Allow", "Principal": "*"}}'), ['*'])


def build(users=(), roles=()):
    data = account_data(users=users, roles=roles)
    graph = IAMGraph()
    graph.build_from_data(data['users'], data['roles'], ACCOUNT, PolicyEngine(data))
    nodes, edges = graph.get_nodes_and_edges()
    return {n['id']: n for n in nodes}, {(e['source'], e['target'], e['label']) for e in edges}


class GraphIdentityTests(unittest.TestCase):
    def test_external_role_does_not_merge_with_local_user(self):
        external_admin = arn("role", "admin", OTHER)
        nodes, edges = build(users=[user("admin")], roles=[role("target", trust_policy=trust({"AWS": external_admin}))])

        self.assertEqual(nodes[arn("user", "admin")]['type'], "USER")
        self.assertEqual(nodes[external_admin]['type'], "EXTERNAL_ACCOUNT")
        self.assertEqual(nodes[external_admin]['label'], f"admin ({OTHER})")
        self.assertEqual(edges, {(external_admin, arn("role", "target"), "CAN_ASSUME")})

    def test_local_user_and_role_with_same_name_are_separate(self):
        nodes, _ = build(users=[user("admin")], roles=[role("admin")])
        self.assertEqual(nodes[arn("user", "admin")]['label'], "admin")
        self.assertEqual(nodes[arn("role", "admin")]['label'], "admin")

    def test_external_account_root_and_bare_account_id(self):
        nodes, edges = build(roles=[role("a", trust_policy=trust({"AWS": f"arn:aws:iam::{OTHER}:root"})),
                                    role("b", trust_policy=trust({"AWS": OTHER}))])
        other_root = f"arn:aws:iam::{OTHER}:root"
        self.assertEqual(nodes[other_root]['type'], "EXTERNAL_ACCOUNT")
        self.assertEqual(nodes[other_root]['label'], f"Account {OTHER}")
        self.assertIn((other_root, arn("role", "b"), "CAN_ASSUME"), edges)

    def test_service_federated_and_public_nodes(self):
        nodes, edges = build(roles=[
            role("svc", trust_policy=trust({"Service": "lambda.amazonaws.com"})),
            role("fed", trust_policy=trust({"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"})),
            role("pub", trust_policy=trust("*")),
        ])
        self.assertEqual(nodes["lambda.amazonaws.com"]['type'], "SERVICE")
        self.assertEqual(nodes[f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"]['type'], "FEDERATED")
        self.assertEqual(nodes[f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"]['label'], "Okta")
        self.assertEqual(nodes["*"]['type'], "PUBLIC")
        self.assertEqual(nodes["*"]['label'], "Anyone (Public)")
        self.assertIn(("*", arn("role", "pub"), "CAN_ASSUME"), edges)

    def test_unique_id_principal_is_unknown(self):
        nodes, _ = build(roles=[role("r", trust_policy=trust({"AWS": "AROAEXAMPLEDELETEDID"}))])
        self.assertEqual(nodes["AROAEXAMPLEDELETEDID"]['type'], "UNKNOWN")


class GraphAssumeRoleTests(unittest.TestCase):
    def test_specific_same_account_arn_gets_edge_without_permissions(self):
        _, edges = build(users=[user("dev"), user("other")],
                         roles=[role("deploy", trust_policy=trust({"AWS": arn("user", "dev")}))])
        self.assertEqual(edges, {(arn("user", "dev"), arn("role", "deploy"), "CAN_ASSUME")})

    def test_single_account_root_node(self):
        nodes, _ = build(roles=[role("a", trust_policy=trust({"AWS": ROOT_ARN})),
                                role("b", trust_policy=trust({"AWS": ACCOUNT}))])
        roots = [n for n in nodes.values() if n['type'] == "ACCOUNT_ROOT"]
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]['label'], "Account Root")

    def test_root_trust_uses_effective_permissions(self):
        deploy = arn("role", "deploy")
        nodes, edges = build(
            users=[
                user("admin", managed=[ADMIN_ARN]),
                user("scoped", inline=[doc(allow("sts:AssumeRole", deploy))]),
                user("wildcard", inline=[doc(allow("sts:Assume*"))]),
                user("other_role_only", inline=[doc(allow("sts:AssumeRole", arn("role", "elsewhere")))]),
                user("denied", managed=[ADMIN_ARN], inline=[doc(deny("sts:AssumeRole", deploy))]),
                user("nothing"),
            ],
            roles=[role("deploy", trust_policy=trust({"AWS": ROOT_ARN})),
                   role("ci", inline=[doc(allow("sts:AssumeRole"))])],
        )
        can_assume = {s for s, t, label in edges if t == deploy and label == "CAN_ASSUME"}
        self.assertEqual(can_assume, {arn("user", "admin"), arn("user", "scoped"), arn("user", "wildcard"), arn("role", "ci")})
        self.assertIn((ROOT_ARN, deploy, "TRUSTS"), edges)

    def test_role_is_not_linked_to_itself(self):
        _, edges = build(roles=[role("self", managed=[ADMIN_ARN], trust_policy=trust({"AWS": ROOT_ARN}))])
        self.assertNotIn((arn("role", "self"), arn("role", "self"), "CAN_ASSUME"), edges)

    def test_assumed_role_session_maps_to_role(self):
        session = f"arn:aws:sts::{ACCOUNT}:assumed-role/ci/session-1"
        _, edges = build(roles=[role("ci"), role("deploy", trust_policy=trust({"AWS": session}))])
        into_deploy = {e for e in edges if e[1] == arn("role", "deploy")}
        self.assertEqual(into_deploy, {(arn("role", "ci"), arn("role", "deploy"), "CAN_ASSUME")})
