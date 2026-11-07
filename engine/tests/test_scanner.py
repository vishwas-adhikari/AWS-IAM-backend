from collections import Counter
from datetime import datetime
from unittest import mock

import boto3
from botocore.stub import Stubber
from django.test import TestCase

from core.models import Finding, GraphNode
from core.serializers import ScanSerializer
from engine import aws_wrapper, scanner
from engine.tests.helpers import ADMIN_ARN, account_data, allow, deny, doc, group, role, trust, user

NO_MFA_TITLE = "Admin Access without MFA"


def run_scan(data):
    with mock.patch.object(scanner.aws_wrapper, "fetch_account_data", return_value=data), \
         mock.patch.object(scanner.notifier, "send_telegram_report"):
        scan = scanner.run_full_scan("test-profile")
    return list(Finding.objects.filter(scan=scan).values_list("affected_resource", "title"))


def report_row(name, mfa):
    return {"user": name, "mfa_active": "true" if mfa else "false"}


class AdminMfaTests(TestCase):
    def no_mfa_users(self, **extra):
        users = [user(n, managed=[ADMIN_ARN]) for n in ("with_mfa", "without_mfa")]
        findings = run_scan(account_data(users=users, **extra))
        return sorted(r for r, title in findings if title == NO_MFA_TITLE)

    def test_credential_report_mfa_active(self):
        rows = [report_row("with_mfa", True), report_row("without_mfa", False)]
        self.assertEqual(self.no_mfa_users(credential_report=rows), ["without_mfa"])

    def test_fallback_to_list_mfa_devices(self):
        devices = {"with_mfa": ["arn:aws:iam::111111111111:mfa/with_mfa"], "without_mfa": []}
        self.assertEqual(self.no_mfa_users(mfa_devices=devices), ["without_mfa"])

    def test_report_wins_over_fallback(self):
        rows = [report_row("with_mfa", True), report_row("without_mfa", False)]
        devices = {"with_mfa": [], "without_mfa": ["arn:aws:iam::111111111111:mfa/x"]}
        self.assertEqual(self.no_mfa_users(credential_report=rows, mfa_devices=devices), ["without_mfa"])

    def test_unknown_mfa_status_is_not_flagged(self):
        self.assertEqual(self.no_mfa_users(mfa_devices={"with_mfa": None, "without_mfa": None}), [])


class ScannerPermissionTests(TestCase):
    def test_findings(self):
        user_names = ("grp_admin", "narrow_deny_admin", "locked_admin", "ops", "s3")
        data = account_data(
            users=[
                user("grp_admin", groups=["admins"]),
                user("narrow_deny_admin", managed=[ADMIN_ARN], inline=[doc(deny("s3:DeleteBucket"))]),
                user("locked_admin", managed=[ADMIN_ARN], inline=[doc(deny("iam:PutUserPolicy"))]),
                user("ops", inline=[doc(allow("iam:Attach*"))]),
                user("s3", inline=[doc(allow(["s3:*", "iam:PassRole"]))]),
            ],
            groups=[group("admins", managed=[ADMIN_ARN])],
            roles=[
                role("r_admin", managed=[ADMIN_ARN]),
                role("r_dupe", inline=[doc(allow("s3:*")), doc(allow("s3:*"))]),
            ],
            credential_report=[report_row(n, True) for n in user_names],
        )
        findings = run_scan(data)

        self.assertEqual([k for k, v in Counter(findings).items() if v > 1], [])
        self.assertEqual(sorted(findings), sorted([
            ("grp_admin", "Full Administrator Access"),
            ("narrow_deny_admin", "Full Administrator Access"),
            # Not admin (can't remove its Deny), but iam:AttachUserPolicy on itself is a path back to admin.
            # No "Broad Wildcard" finding: that rule is for service-wide grants like s3:*, not "*".
            ("locked_admin", "Privilege Escalation Path"),
            ("locked_admin", "PassRole to Any Resource"),
            ("ops", "Privilege Escalation Path"),
            ("s3", "Broad Wildcard Permissions"),
            ("s3", "PassRole to Any Resource"),
            ("r_admin", "Full Administrator Access"),
            ("r_dupe", "Broad Wildcard Permissions"),
        ]))


class GraphRiskTests(TestCase):
    def test_risk_is_mapped_by_arn_not_name(self):
        data = account_data(
            users=[user("admin", managed=[ADMIN_ARN])],
            roles=[role("admin"), role("public", trust_policy=trust("*"))],
            credential_report=[report_row("admin", True)],
        )
        with mock.patch.object(scanner.aws_wrapper, "fetch_account_data", return_value=data), \
             mock.patch.object(scanner.notifier, "send_telegram_report"):
            scan = scanner.run_full_scan()

        risk = dict(GraphNode.objects.filter(scan=scan).values_list("node_id", "risk_level"))
        self.assertEqual(risk["arn:aws:iam::111111111111:user/admin"], "CRITICAL")
        self.assertEqual(risk["arn:aws:iam::111111111111:role/admin"], "LOW")
        self.assertEqual(risk["arn:aws:iam::111111111111:role/public"], "CRITICAL")
        self.assertEqual(risk["*"], "CRITICAL")


class FindingFieldsTests(TestCase):
    def test_rule_id_and_details_are_saved_and_serialized(self):
        data = account_data(users=[user("admin", managed=[ADMIN_ARN])], credential_report=[report_row("admin", True)])
        with mock.patch.object(scanner.aws_wrapper, "fetch_account_data", return_value=data), \
             mock.patch.object(scanner.notifier, "send_telegram_report"):
            scan = scanner.run_full_scan()

        finding = Finding.objects.get(scan=scan, affected_resource="admin")
        self.assertEqual(finding.rule_id, "ADMIN_ACCESS")
        self.assertEqual(finding.details, {})

        serialized = ScanSerializer(scan).data["findings"][0]
        self.assertEqual(serialized["rule_id"], "ADMIN_ACCESS")
        self.assertEqual(serialized["details"], {})

    def test_create_finding_overrides(self):
        finding = scanner.create_finding(None, "ADMIN_ACCESS", "x", description="custom", details={"k": [1]})
        self.assertEqual((finding.description, finding.details), ("custom", {"k": [1]}))


class FetchMfaDevicesTests(TestCase):
    def test_lists_devices_and_marks_errors_unknown(self):
        iam = boto3.client("iam", region_name="us-east-1", aws_access_key_id="a", aws_secret_access_key="b")
        with Stubber(iam) as stub:
            stub.add_response("list_mfa_devices", {"MFADevices": [], "IsTruncated": False}, {"UserName": "none"})
            stub.add_response("list_mfa_devices", {"MFADevices": [{
                "UserName": "one", "SerialNumber": "arn:aws:iam::111111111111:mfa/one",
                "EnableDate": datetime(2024, 1, 1)}], "IsTruncated": False}, {"UserName": "one"})
            stub.add_client_error("list_mfa_devices", "AccessDenied", expected_params={"UserName": "denied"})
            result = aws_wrapper.fetch_mfa_devices(iam, ["none", "one", "denied"])
        self.assertEqual(result, {"none": [], "one": ["arn:aws:iam::111111111111:mfa/one"], "denied": None})


class PrivilegeEscalationFindingTests(TestCase):
    def scan(self, data):
        with mock.patch.object(scanner.aws_wrapper, "fetch_account_data", return_value=data), \
             mock.patch.object(scanner.notifier, "send_telegram_report"):
            return scanner.run_full_scan()

    def test_path_is_saved_with_hops(self):
        data = account_data(
            users=[user("Intern-Dave")],
            roles=[role("Maintenance-Role", managed=[ADMIN_ARN],
                        trust_policy=trust({"AWS": "arn:aws:iam::111111111111:user/Intern-Dave"}))],
        )
        scan = self.scan(data)

        finding = Finding.objects.get(scan=scan, rule_id="PRIVILEGE_ESCALATION")
        self.assertEqual(finding.affected_resource, "Intern-Dave")
        self.assertEqual(finding.description, "Path to admin: Intern-Dave -> Maintenance-Role [CAN_ASSUME]")
        self.assertEqual([h["to"] for h in finding.details["hops"]],
                         ["arn:aws:iam::111111111111:role/Maintenance-Role"])

    def test_every_node_on_a_path_is_critical(self):
        acct = "arn:aws:iam::111111111111"
        data = account_data(
            users=[user("dev"), user("boss", managed=[ADMIN_ARN]), user("bystander")],
            roles=[role("ci", inline=[doc(allow("iam:CreateAccessKey", f"{acct}:user/boss"))],
                        trust_policy=trust({"AWS": f"{acct}:user/dev"}))],
            credential_report=[report_row("boss", True)],
        )
        scan = self.scan(data)
        risk = dict(GraphNode.objects.filter(scan=scan).values_list("node_id", "risk_level"))
        for name in ("user/dev", "role/ci", "user/boss"):
            self.assertEqual(risk[f"{acct}:{name}"], "CRITICAL", name)
        self.assertEqual(risk[f"{acct}:user/bystander"], "LOW")
