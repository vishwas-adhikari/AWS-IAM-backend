import os
import tempfile
from pathlib import Path
from unittest import mock

import boto3
from botocore.exceptions import NoCredentialsError
from botocore.stub import Stubber
from django.test import TestCase
from rest_framework.test import APIClient

from core.models import Scan
from engine import aws_wrapper, scanner

SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

AWS_CONFIG = """\
[default]
region = us-east-1

[profile dev]
region = eu-west-1
"""
AWS_CREDENTIALS = f"""\
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = {SECRET}

[prod]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = {SECRET}
"""


class AwsConfigFilesMixin:
    """Points boto3 at throwaway config/credentials files instead of the real ~/.aws."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config, credentials = Path(tmp.name, "config"), Path(tmp.name, "credentials")
        config.write_text(AWS_CONFIG)
        credentials.write_text(AWS_CREDENTIALS)

        env = mock.patch.dict(os.environ, {
            "AWS_CONFIG_FILE": str(config),
            "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
        })
        env.start()
        self.addCleanup(env.stop)
        for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
            os.environ.pop(var, None)


class ProfileListViewTests(AwsConfigFilesMixin, TestCase):
    def test_lists_profile_names_only(self):
        response = APIClient().get("/api/profiles/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"profiles": ["default", "dev", "prod"]})
        self.assertNotIn(SECRET, response.content.decode())
        self.assertNotIn("AKIA", response.content.decode())

    def test_config_error_returns_clean_message(self):
        with mock.patch.object(aws_wrapper, "list_profiles", side_effect=RuntimeError("bad file C:/secret/path")), \
             self.assertLogs("core.views", level="ERROR"):
            response = APIClient().get("/api/profiles/")

        self.assertEqual(response.status_code, 500)
        self.assertNotIn("secret/path", response.content.decode())


def stubbed_session(configure):
    """A fake boto3 session whose sts/iam clients are botocore-stubbed by `configure(stubs)`."""
    clients = {name: boto3.client(name, region_name="us-east-1", aws_access_key_id="a", aws_secret_access_key="b")
               for name in ("sts", "iam")}
    stubs = {name: Stubber(client) for name, client in clients.items()}
    configure(stubs)
    for stub in stubs.values():
        stub.activate()
    session = mock.Mock()
    session.client.side_effect = lambda name: clients[name]
    return session


CALLER = {"Account": "111111111111", "Arn": "arn:aws:iam::111111111111:user/scanner", "UserId": "AIDAEXAMPLE"}
RAW_AWS_MESSAGE = "The security token included in the request is invalid. RequestId abc-123"


class StartScanViewTests(AwsConfigFilesMixin, TestCase):
    def post(self, body):
        return APIClient().post("/api/scan/", body, format="json")

    def assert_clean_error(self, response, status_code, message):
        self.assertEqual(response.status_code, status_code)
        self.assertEqual(response.json(), {"error": message})
        self.assertNotIn("RequestId", response.content.decode())

    # --- request handling ---

    def test_passes_profile_to_scanner(self):
        scan = Scan.objects.create(account_id="111111111111")
        with mock.patch.object(scanner, "run_full_scan", return_value=scan) as run:
            response = self.post({"profile": "dev"})

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["account_id"], "111111111111")
        run.assert_called_once_with("dev")

    def test_missing_or_empty_profile_uses_default_chain(self):
        scan = Scan.objects.create(account_id="111111111111")
        for body in ({}, {"profile": ""}, {"profile": None}):
            with self.subTest(body=body), mock.patch.object(scanner, "run_full_scan", return_value=scan) as run:
                self.assertEqual(self.post(body).status_code, 201)
                run.assert_called_once_with(None)

    def test_non_string_profile_rejected(self):
        with mock.patch.object(scanner, "run_full_scan") as run:
            response = self.post({"profile": ["dev"]})
        self.assertEqual(response.status_code, 400)
        run.assert_not_called()

    def test_old_key_payload_is_not_used(self):
        scan = Scan.objects.create(account_id="111111111111")
        with mock.patch.object(scanner, "run_full_scan", return_value=scan) as run:
            self.post({"access_key": "AKIA...", "secret_key": SECRET})
        run.assert_called_once_with(None)

    # --- error handling (real wrapper, stubbed AWS) ---

    def test_unknown_profile(self):
        with self.assertLogs("core.views", level="WARNING") as logs:
            response = self.post({"profile": "does-not-exist"})

        self.assert_clean_error(response, 400, "Unknown AWS profile.")
        self.assertIn("does-not-exist", "\n".join(logs.output))

    def test_invalid_credentials(self):
        session = stubbed_session(lambda s: s["sts"].add_client_error(
            "get_caller_identity", "InvalidClientTokenId", RAW_AWS_MESSAGE, http_status_code=403))
        with mock.patch.object(aws_wrapper, "get_session", return_value=session), \
             self.assertLogs("core.views", level="WARNING") as logs:
            response = self.post({"profile": "dev"})

        self.assert_clean_error(response, 401, "The AWS credentials for this profile are invalid or expired.")
        self.assertNotIn("security token", response.content.decode())
        self.assertIn("InvalidClientTokenId", "\n".join(logs.output))

    def test_missing_credentials(self):
        session = mock.Mock()
        session.client.return_value.get_caller_identity.side_effect = NoCredentialsError()
        with mock.patch.object(aws_wrapper, "get_session", return_value=session), \
             self.assertLogs("core.views", level="WARNING"):
            response = self.post({})

        self.assert_clean_error(response, 401, "The AWS credentials for this profile are invalid or expired.")

    def test_access_denied(self):
        def configure(stubs):
            stubs["sts"].add_response("get_caller_identity", CALLER)
            stubs["iam"].add_client_error(
                "get_account_authorization_details", "AccessDenied",
                "User: arn:aws:iam::111111111111:user/scanner is not authorized. RequestId abc-123",
                http_status_code=403)

        with mock.patch.object(aws_wrapper, "get_session", return_value=stubbed_session(configure)), \
             self.assertLogs("core.views", level="WARNING") as logs:
            response = self.post({"profile": "dev"})

        self.assert_clean_error(response, 403, "Access denied. The credentials need the AWS-managed SecurityAudit policy.")
        self.assertNotIn("arn:aws:iam", response.content.decode())
        self.assertIn("AccessDenied", "\n".join(logs.output))

    def test_unexpected_error_is_generic(self):
        with mock.patch.object(scanner, "run_full_scan", side_effect=ValueError("internal detail RequestId xyz")), \
             self.assertLogs("core.views", level="ERROR") as logs:
            response = self.post({"profile": "dev"})

        self.assert_clean_error(response, 500, "The scan failed. Check the server logs for details.")
        self.assertIn("internal detail", "\n".join(logs.output))
