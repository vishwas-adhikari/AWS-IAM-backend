import unittest

from engine.policy_engine import DENY_REMOVAL_ACTIONS, PolicyEngine, _covers, _overlaps
from engine.tests.helpers import ADMIN_ARN, account_data, allow, deny, doc, group, role, user

POWER_USER_ARN = 'arn:aws:iam::aws:policy/PowerUserAccess'
CUSTOM_ARN = 'arn:aws:iam::111111111111:policy/CustomAdmin'
NO_MFA = {"Bool": {"aws:MultiFactorAuthPresent": "false"}}


def engine_for(*users, roles=(), groups=(), managed_policies=None):
    return PolicyEngine(account_data(users=users, roles=roles, groups=groups, managed_policies=managed_policies))


def is_admin_with(*statements):
    """is_admin for a user whose single inline policy holds `statements`."""
    return engine_for(user("u", inline=[doc(*statements)])).is_admin({"UserName": "u"})


class PatternTests(unittest.TestCase):
    def test_covers(self):
        self.assertTrue(_covers("iam:*", "iam:attach*"))
        self.assertTrue(_covers("*", "iam:attachuserpolicy"))
        self.assertFalse(_covers("iam:attach*", "iam:*"))

    def test_overlaps(self):
        self.assertTrue(_overlaps("iam:a*", "*policy"))
        self.assertFalse(_overlaps("s3:*", "iam:*"))


class AdminSourceTests(unittest.TestCase):
    def test_administrator_access_on_role(self):
        e = engine_for(roles=[role("r", managed=[ADMIN_ARN])])
        self.assertTrue(e.is_admin({"RoleName": "r"}))

    def test_administrator_access_via_group(self):
        e = engine_for(user("u", groups=["admins"]), groups=[group("admins", managed=[ADMIN_ARN])])
        self.assertTrue(e.is_admin({"UserName": "u"}))

    def test_custom_policy_granting_star(self):
        e = engine_for(user("u", managed=[CUSTOM_ARN]), managed_policies={
            CUSTOM_ARN: {"Document": '{"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}'}})
        self.assertTrue(e.is_admin({"UserName": "u"}))

    def test_inline_star_on_role(self):
        e = engine_for(roles=[role("r", inline=[doc(allow("*"))])])
        self.assertTrue(e.is_admin({"RoleName": "r"}))

    def test_administrator_access_fallback_when_unresolved(self):
        e = engine_for(user("u", managed=[ADMIN_ARN]), managed_policies={})
        self.assertTrue(e.is_admin({"UserName": "u"}))

    def test_power_user_is_not_admin(self):
        e = engine_for(user("u", managed=[POWER_USER_ARN]), managed_policies={POWER_USER_ARN: {"Document": doc(
            {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"})}})
        self.assertFalse(e.is_admin({"UserName": "u"}))
        self.assertTrue(e.allows({"UserName": "u"}, "ec2:RunInstances"))
        self.assertFalse(e.allows({"UserName": "u"}, "iam:CreateUser"))

    def test_not_resource_is_not_admin(self):
        e = engine_for(user("u", inline=[doc({"Effect": "Allow", "Action": "*", "NotResource": "arn:aws:s3:::secret/*"})]))
        self.assertFalse(e.is_admin({"UserName": "u"}))
        self.assertTrue(e.allows({"UserName": "u"}, "s3:GetObject", "arn:aws:s3:::public/x"))
        self.assertFalse(e.allows({"UserName": "u"}, "s3:GetObject", "arn:aws:s3:::secret/x"))


class AdminDenyTests(unittest.TestCase):
    """Allow *:* combined with various Deny statements."""

    def test_narrow_deny_keeps_admin(self):
        self.assertTrue(is_admin_with(allow("*"), deny("s3:DeleteBucket")))

    def test_deny_star_on_non_iam_resource_keeps_admin(self):
        self.assertTrue(is_admin_with(allow("*"), deny("*", "arn:aws:s3:::prod-bucket/*")))

    def test_deny_on_each_removal_action_removes_admin(self):
        for action in DENY_REMOVAL_ACTIONS:
            with self.subTest(action=action):
                self.assertFalse(is_admin_with(allow("*"), deny("s3:DeleteBucket"), deny(action)))

    def test_deny_removal_action_on_own_arn_removes_admin(self):
        self.assertFalse(is_admin_with(allow("*"), deny("iam:DeleteUserPolicy", "arn:aws:iam::111111111111:user/u")))

    def test_deny_iam_wildcard_removes_admin(self):
        self.assertFalse(is_admin_with(allow("*"), deny("iam:*")))

    def test_full_deny_removes_admin(self):
        self.assertFalse(is_admin_with(allow("*"), deny("*")))

    def test_deny_not_action_covering_iam_removes_admin(self):
        self.assertFalse(is_admin_with(allow("*"), {"Effect": "Deny", "NotAction": "s3:*", "Resource": "*"}))

    def test_conditional_deny_is_ignored(self):
        self.assertTrue(is_admin_with(allow("*"), deny("*", Condition=NO_MFA)))

    def test_conditional_allow_alone_is_admin(self):
        self.assertTrue(is_admin_with(allow("*", Condition=NO_MFA)))

    def test_conditional_allow_with_narrow_deny_is_admin(self):
        self.assertTrue(is_admin_with(allow("*", Condition=NO_MFA), deny("s3:DeleteBucket")))

    def test_conditional_allow_with_removal_deny_is_not_admin(self):
        self.assertFalse(is_admin_with(allow("*", Condition=NO_MFA), deny("iam:DetachUserPolicy")))

    def test_deny_via_group_removes_admin(self):
        e = engine_for(user("u", managed=[ADMIN_ARN], groups=["locked"]),
                       groups=[group("locked", inline=[doc(deny("iam:Detach*"))])])
        self.assertFalse(e.is_admin({"UserName": "u"}))


class AllowsTests(unittest.TestCase):
    def test_case_insensitive_action_wildcards(self):
        e = engine_for(user("u", groups=["ops"]), groups=[group("ops", inline=[doc(allow("IAM:Attach*"))])])
        self.assertTrue(e.allows({"UserName": "u"}, "iam:attachrolepolicy"))
        self.assertFalse(e.allows({"UserName": "u"}, "iam:CreatePolicy"))

    def test_deny_overrides_allow(self):
        e = engine_for(user("u", inline=[doc(allow("s3:*")), doc(deny("s3:DeleteBucket"))]))
        self.assertTrue(e.allows({"UserName": "u"}, "s3:GetObject"))
        self.assertFalse(e.allows({"UserName": "u"}, "s3:DeleteBucket"))
        self.assertEqual(e.service_wildcards({"UserName": "u"}), [])

    def test_scoped_grant(self):
        e = engine_for(user("u", inline=[doc(allow("iam:CreateAccessKey", "arn:aws:iam::111111111111:user/u"))]))
        self.assertFalse(e.allows({"UserName": "u"}, "iam:CreateAccessKey"))
        self.assertTrue(e.allows_on_any_resource({"UserName": "u"}, "iam:CreateAccessKey"))

    def test_unresolved_policy_recorded(self):
        missing = 'arn:aws:iam::aws:policy/Missing'
        e = engine_for(user("u", managed=[missing]))
        self.assertEqual(e.get({"UserName": "u"}).unresolved_policies, [missing])

    def test_lookup_by_arn(self):
        e = engine_for(roles=[role("r", managed=[ADMIN_ARN])])
        self.assertTrue(e.is_admin("arn:aws:iam::111111111111:role/r"))
