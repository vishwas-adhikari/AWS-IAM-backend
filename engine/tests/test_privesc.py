from django.test import SimpleTestCase

from engine import graph_builder, policy_engine, privesc
from engine.tests.helpers import ACCOUNT, ADMIN_ARN, account_data, allow, deny, doc, group, role, trust, user

CUSTOM_ARN = f"arn:aws:iam::{ACCOUNT}:policy/custom"
ADMIN_NODE = privesc.admin_node_id(ACCOUNT)


def arn(kind, name):
    return f"arn:aws:iam::{ACCOUNT}:{kind}/{name}"


def analyze(**kwargs):
    data = account_data(**kwargs)
    engine = policy_engine.PolicyEngine(data)
    graph = graph_builder.IAMGraph()
    graph.build_from_data(data["users"], data["roles"], data["account_id"], engine)
    paths = privesc.analyze(graph, engine, data)
    return {p["source"]: p for p in paths}, graph


def chain(path):
    """[(edge, to), ...] for compact assertions."""
    return [(h["edge"], h["to"]) for h in path["hops"]]


class SelfEscalationTests(SimpleTestCase):
    def test_attach_user_policy_on_self(self):
        paths, _ = analyze(users=[user("dev", inline=[doc(allow("iam:AttachUserPolicy", arn("user", "dev")))])])
        self.assertEqual(chain(paths[arn("user", "dev")]), [("CAN_SELF_ESCALATE", ADMIN_NODE)])
        self.assertEqual(paths[arn("user", "dev")]["hops"][0]["techniques"], ["iam:AttachUserPolicy"])

    def test_wildcard_action_counts(self):
        paths, _ = analyze(users=[user("ops", inline=[doc(allow("iam:Attach*"))])])
        self.assertIn(arn("user", "ops"), paths)

    def test_put_role_policy_on_self(self):
        paths, _ = analyze(roles=[role("worker", inline=[doc(allow("iam:PutRolePolicy", arn("role", "worker")))])])
        self.assertIn(arn("role", "worker"), paths)

    def test_create_policy_version_on_own_customer_policy(self):
        managed = {ADMIN_ARN: {"Document": doc(allow("*"))},
                   CUSTOM_ARN: {"Document": doc(allow("iam:CreatePolicyVersion", CUSTOM_ARN))}}
        paths, _ = analyze(users=[user("dev", managed=[CUSTOM_ARN])], managed_policies=managed)
        self.assertEqual(paths[arn("user", "dev")]["hops"][0]["techniques"], ["iam:CreatePolicyVersion"])

    def test_create_policy_version_ignores_aws_managed(self):
        ro = "arn:aws:iam::aws:policy/ReadOnlyAccess"
        managed = {ADMIN_ARN: {"Document": doc(allow("*"))},
                   ro: {"Document": doc(allow("iam:CreatePolicyVersion"))}}
        paths, graph = analyze(users=[user("dev", managed=[ro])], managed_policies=managed)
        self.assertEqual(paths, {})
        self.assertFalse(graph.graph.has_node(ADMIN_NODE))  # no edge at all, not just no path

    def test_add_user_to_admin_group(self):
        paths, _ = analyze(
            users=[user("dev", inline=[doc(allow("iam:AddUserToGroup", arn("group", "admins")))])],
            groups=[group("admins", managed=[ADMIN_ARN]), group("readers")],
        )
        self.assertEqual(paths[arn("user", "dev")]["hops"][0]["techniques"], ["iam:AddUserToGroup (admins)"])

    def test_add_user_to_non_admin_group_is_not_escalation(self):
        paths, _ = analyze(
            users=[user("dev", inline=[doc(allow("iam:AddUserToGroup", arn("group", "readers")))])],
            groups=[group("admins", managed=[ADMIN_ARN]), group("readers")],
        )
        self.assertEqual(paths, {})

    def test_attach_policy_to_own_group(self):
        paths, _ = analyze(
            users=[user("dev", groups=["devs"])],
            groups=[group("devs", inline=[doc(allow("iam:AttachGroupPolicy", arn("group", "devs")))])],
        )
        self.assertIn(arn("user", "dev"), paths)

    def test_explicit_deny_blocks(self):
        paths, _ = analyze(users=[user("dev", inline=[doc(allow("iam:AttachUserPolicy"), deny("iam:*"))])])
        self.assertEqual(paths, {})

    def test_create_policy_alone_is_not_escalation(self):
        paths, _ = analyze(users=[user("dev", inline=[doc(allow("iam:CreatePolicy"))])])
        self.assertEqual(paths, {})


class TakeoverTests(SimpleTestCase):
    def test_create_access_key_on_admin_user(self):
        paths, _ = analyze(users=[
            user("helpdesk", inline=[doc(allow("iam:CreateAccessKey", arn("user", "boss")))]),
            user("boss", managed=[ADMIN_ARN]),
        ])
        self.assertEqual(chain(paths[arn("user", "helpdesk")]), [("CAN_TAKE_OVER", arn("user", "boss"))])

    def test_update_login_profile(self):
        paths, _ = analyze(users=[
            user("helpdesk", inline=[doc(allow("iam:UpdateLoginProfile", arn("user", "boss")))]),
            user("boss", managed=[ADMIN_ARN]),
        ])
        self.assertIn(arn("user", "helpdesk"), paths)

    def test_takeover_of_non_admin_is_not_a_path(self):
        paths, graph = analyze(users=[
            user("helpdesk", inline=[doc(allow("iam:CreateAccessKey", arn("user", "intern")))]),
            user("intern"),
        ])
        self.assertEqual(paths, {})
        # ...but the edge is still drawn, so it shows in the graph
        self.assertTrue(graph.graph.has_edge(arn("user", "helpdesk"), arn("user", "intern")))


class RoleTests(SimpleTestCase):
    def test_assume_admin_role_trusted_directly(self):
        # The original "Intern-Dave" case study
        paths, _ = analyze(
            users=[user("dave")],
            roles=[role("maint", managed=[ADMIN_ARN], trust_policy=trust({"AWS": arn("user", "dave")}))],
        )
        self.assertEqual(chain(paths[arn("user", "dave")]), [("CAN_ASSUME", arn("role", "maint"))])

    def test_assume_via_account_root_needs_identity_permission(self):
        root_trust = trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"})
        paths, _ = analyze(
            users=[user("dave", inline=[doc(allow("sts:AssumeRole", arn("role", "maint")))]), user("eve")],
            roles=[role("maint", managed=[ADMIN_ARN], trust_policy=root_trust)],
        )
        self.assertIn(arn("user", "dave"), paths)
        self.assertNotIn(arn("user", "eve"), paths)

    def test_update_assume_role_policy(self):
        paths, _ = analyze(
            users=[user("dev", inline=[doc(allow("iam:UpdateAssumeRolePolicy", arn("role", "maint")))])],
            roles=[role("maint", managed=[ADMIN_ARN])],
        )
        self.assertEqual(chain(paths[arn("user", "dev")]), [("CAN_MODIFY_TRUST", arn("role", "maint"))])

    def test_pass_role_to_lambda(self):
        lambda_trust = trust({"Service": "lambda.amazonaws.com"})
        paths, _ = analyze(
            users=[user("dev", inline=[doc(allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]))])],
            roles=[role("fn", managed=[ADMIN_ARN], trust_policy=lambda_trust)],
        )
        hop = paths[arn("user", "dev")]["hops"][0]
        self.assertEqual(hop["edge"], "CAN_PASS_ROLE")
        self.assertEqual(hop["techniques"], ["iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction"])

    def test_pass_role_to_ec2(self):
        paths, _ = analyze(
            users=[user("dev", inline=[doc(allow(["iam:PassRole", "ec2:RunInstances"]))])],
            roles=[role("box", managed=[ADMIN_ARN])],  # helper default trusts ec2
        )
        self.assertEqual(chain(paths[arn("user", "dev")]), [("CAN_PASS_ROLE", arn("role", "box"))])

    def test_pass_role_needs_matching_service_trust(self):
        # Role trusts EC2, user can only create Lambda functions
        paths, _ = analyze(
            users=[user("dev", inline=[doc(allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]))])],
            roles=[role("box", managed=[ADMIN_ARN], trust_policy=trust({"Service": "ec2.amazonaws.com"}))],
        )
        self.assertEqual(paths, {})

    def test_pass_role_without_compute_action(self):
        paths, _ = analyze(
            users=[user("dev", inline=[doc(allow("iam:PassRole"))])],
            roles=[role("box", managed=[ADMIN_ARN])],
        )
        self.assertEqual(paths, {})


class ChainTests(SimpleTestCase):
    def test_multi_hop_chain(self):
        # dev -> assume ci role -> ci takes over boss (admin)
        paths, _ = analyze(
            users=[user("dev"), user("boss", managed=[ADMIN_ARN])],
            roles=[role("ci", inline=[doc(allow("iam:CreateAccessKey", arn("user", "boss")))],
                        trust_policy=trust({"AWS": arn("user", "dev")}))],
        )
        self.assertEqual(chain(paths[arn("user", "dev")]), [
            ("CAN_ASSUME", arn("role", "ci")),
            ("CAN_TAKE_OVER", arn("user", "boss")),
        ])
        # the intermediate role gets its own one-hop finding too
        self.assertEqual(len(paths[arn("role", "ci")]["hops"]), 1)

    def test_public_role_to_admin(self):
        paths, _ = analyze(roles=[role("open", managed=[ADMIN_ARN], trust_policy=trust("*"))])
        self.assertEqual(chain(paths["*"]), [("CAN_ASSUME", arn("role", "open"))])

    def test_shortest_path_wins(self):
        paths, _ = analyze(
            users=[user("dev", inline=[doc(allow("iam:PutUserPolicy", arn("user", "dev")))]),
                   user("boss", managed=[ADMIN_ARN])],
            roles=[role("hop", inline=[doc(allow("iam:CreateAccessKey", arn("user", "boss")))],
                        trust_policy=trust({"AWS": arn("user", "dev")}))],
        )
        self.assertEqual(len(paths[arn("user", "dev")]["hops"]), 1)

    def test_admins_are_not_sources(self):
        paths, _ = analyze(users=[user("boss", managed=[ADMIN_ARN])])
        self.assertEqual(paths, {})

    def test_no_path_for_harmless_account(self):
        paths, _ = analyze(
            users=[user("reader", inline=[doc(allow(["s3:GetObject", "iam:List*", "iam:Get*"]))]),
                   user("boss", managed=[ADMIN_ARN])],
            roles=[role("maint", managed=[ADMIN_ARN])],
        )
        self.assertEqual(paths, {})

    def test_trusts_edge_is_not_traversable(self):
        # Root trust without identity permission: nobody can assume it
        paths, _ = analyze(
            users=[user("eve")],
            roles=[role("maint", managed=[ADMIN_ARN], trust_policy=trust({"AWS": ACCOUNT}))],
        )
        self.assertEqual(paths, {})

    def test_describe(self):
        paths, _ = analyze(
            users=[user("dave")],
            roles=[role("maint", managed=[ADMIN_ARN], trust_policy=trust({"AWS": arn("user", "dave")}))],
        )
        self.assertEqual(privesc.describe(paths[arn("user", "dave")]), "dave -> maint [CAN_ASSUME]")