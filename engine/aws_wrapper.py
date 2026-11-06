import csv
import io
import time

import boto3
from botocore import exceptions as botocore_exceptions
from botocore.exceptions import ClientError

# Every call below is covered by the AWS-managed SecurityAudit policy
# (iam:Get*, iam:List*, iam:GenerateCredentialReport, sts:GetCallerIdentity).

CREDENTIAL_REPORT_MAX_ATTEMPTS = 10
CREDENTIAL_REPORT_RETRY_SECONDS = 2


# --- Errors the API layer can turn into clean messages ---

class AWSScanError(Exception):
    """Base class for AWS problems that stop a scan. The message is safe to show users."""


class ProfileNotFoundError(AWSScanError):
    pass


class InvalidCredentialsError(AWSScanError):
    pass


class AccessDeniedError(AWSScanError):
    pass


# Raised while botocore loads credentials (missing, incomplete, expired SSO session, ...)
CREDENTIAL_LOAD_ERRORS = (
    botocore_exceptions.NoCredentialsError,
    botocore_exceptions.PartialCredentialsError,
    botocore_exceptions.CredentialRetrievalError,
    botocore_exceptions.TokenRetrievalError,
    botocore_exceptions.SSOTokenLoadError,
    botocore_exceptions.UnauthorizedSSOTokenError,
)
# ClientError codes AWS returns for bad, expired or unknown credentials
INVALID_CREDENTIAL_CODES = {
    'InvalidClientTokenId', 'SignatureDoesNotMatch', 'ExpiredToken', 'ExpiredTokenException',
    'UnrecognizedClientException', 'InvalidAccessKeyId', 'AuthFailure',
}
ACCESS_DENIED_CODES = {'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'}


def list_profiles():
    """Names of the AWS profiles configured on this machine (no credentials)."""
    return sorted(boto3.Session().available_profiles)


def get_session(profile=None):
    """
    Creates a Boto3 session from a named profile in ~/.aws/config / ~/.aws/credentials,
    or from the default credential chain (env vars, instance role, ...) when profile is None.
    """
    try:
        return boto3.Session(
            profile_name=profile or None,
            region_name='us-east-1'  # IAM is global, but boto3 needs a region
        )
    except botocore_exceptions.ProfileNotFound as e:
        raise ProfileNotFoundError(f"AWS profile '{profile}' was not found.") from e


def get_iam_client(profile=None):
    """Creates a Boto3 IAM client for the given profile (or the default credential chain)."""
    return get_session(profile).client('iam')


def fetch_authorization_details(iam):
    """Downloads the full IAM snapshot, following pagination so large accounts aren't truncated."""
    paginator = iam.get_paginator('get_account_authorization_details')
    return paginator.paginate(
        Filter=['User', 'Group', 'Role', 'LocalManagedPolicy']
    ).build_full_result()


def resolve_managed_policies(iam, auth_details):
    """
    Returns {policy_arn: {...}} with the default-version document of every managed
    policy attached to a user, group or role (customer-managed and AWS-managed).
    Each policy is fetched at most once.
    """
    cache = {}

    # Customer-managed policies already come back from GetAccountAuthorizationDetails
    # with their version list, so seed the cache from there instead of re-fetching.
    for policy in auth_details.get('Policies', []):
        default_version = next(
            (v for v in policy.get('PolicyVersionList', []) if v.get('IsDefaultVersion')),
            None
        )
        if default_version:
            cache[policy['Arn']] = {
                "PolicyName": policy['PolicyName'],
                "Arn": policy['Arn'],
                "DefaultVersionId": policy.get('DefaultVersionId'),
                "IsAWSManaged": False,
                "Document": default_version.get('Document', {}),
            }

    attached = {}
    for key in ('UserDetailList', 'GroupDetailList', 'RoleDetailList'):
        for entity in auth_details.get(key, []):
            for policy in entity.get('AttachedManagedPolicies', []):
                attached[policy['PolicyArn']] = policy['PolicyName']

    for arn, name in attached.items():
        if arn in cache:
            continue
        try:
            policy = iam.get_policy(PolicyArn=arn)['Policy']
            version = iam.get_policy_version(
                PolicyArn=arn, VersionId=policy['DefaultVersionId']
            )['PolicyVersion']
            cache[arn] = {
                "PolicyName": policy['PolicyName'],
                "Arn": arn,
                "DefaultVersionId": policy['DefaultVersionId'],
                "IsAWSManaged": ':aws:policy/' in arn,
                "Document": version.get('Document', {}),
            }
        except ClientError as e:
            print(f"Could not resolve managed policy {name} ({arn}): {e}")

    return cache


def fetch_credential_report(iam):
    """
    Generates and downloads the IAM credential report (access key ages, last-used
    dates, password/MFA status, root usage). Returns a list of row dicts, or [] if
    the report could not be obtained.
    """
    for _ in range(CREDENTIAL_REPORT_MAX_ATTEMPTS):
        try:
            state = iam.generate_credential_report().get('State')
            if state == 'COMPLETE':
                content = iam.get_credential_report()['Content']
                if isinstance(content, bytes):
                    content = content.decode('utf-8')
                return list(csv.DictReader(io.StringIO(content)))
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code not in ('ReportInProgress', 'ReportNotPresent', 'ReportExpired'):
                print(f"Credential report unavailable: {e}")
                return []
        time.sleep(CREDENTIAL_REPORT_RETRY_SECONDS)

    print("Credential report was not ready in time. Skipping.")
    return []


def fetch_mfa_devices(iam, user_names):
    """
    Fallback for users missing from the credential report.
    Returns {user_name: [serial, ...]}, or None for a user whose devices couldn't be listed.
    """
    devices = {}
    paginator = iam.get_paginator('list_mfa_devices')
    for user_name in user_names:
        try:
            devices[user_name] = [
                d['SerialNumber']
                for page in paginator.paginate(UserName=user_name)
                for d in page.get('MFADevices', [])
            ]
        except ClientError as e:
            print(f"Could not list MFA devices for {user_name}: {e}")
            devices[user_name] = None
    return devices


def fetch_account_summary(iam):
    """Returns the IAM account summary map (includes AccountMFAEnabled, AccountAccessKeysPresent)."""
    try:
        return iam.get_account_summary().get('SummaryMap', {})
    except ClientError as e:
        print(f"Account summary unavailable: {e}")
        return {}


def fetch_account_data(profile=None):
    """
    Orchestrates the data collection:
    1. Verifies Identity (GetCallerIdentity)
    2. Downloads IAM snapshot (GetAccountAuthorizationDetails, paginated)
    3. Resolves attached managed policy documents (GetPolicy + GetPolicyVersion)
    4. Fetches Password Policy (Safe Mode)
    5. Fetches Credential Report and Account Summary
       (plus ListMFADevices for any user the report doesn't cover)
    """
    try:
        session = get_session(profile)

        # 1. Verification & Account ID
        caller_id = session.client('sts').get_caller_identity()
        account_id = caller_id['Account']
        arn = caller_id['Arn']

        # 2. Main IAM Dump (Users, Groups, Roles, Policies)
        iam = session.client('iam')

        print(f"Scanning Account: {account_id}...")
        auth_details = fetch_authorization_details(iam)

        # 3. Managed policy documents (customer- and AWS-managed)
        managed_policies = resolve_managed_policies(iam, auth_details)

        # 4. Get Password Policy (Safely)
        # We initialize it as empty first so the variable always exists
        password_policy = {}
        try:
            # Try to fetch the real policy
            response = iam.get_account_password_policy()
            password_policy = response.get('PasswordPolicy', {})
        except ClientError:
            # If no policy exists, AWS throws an error. We catch it and move on.
            print("No password policy found (or permission denied). Using default.")
            pass

        # 5. Credential Report & Account Summary
        credential_report = fetch_credential_report(iam)
        account_summary = fetch_account_summary(iam)

        # Users the report doesn't cover (report missing, or user newer than the report)
        reported_users = {row.get('user') for row in credential_report}
        mfa_devices = fetch_mfa_devices(iam, [
            u['UserName'] for u in auth_details.get('UserDetailList', [])
            if u['UserName'] not in reported_users
        ])

        # 6. Return everything
        return {
            "account_id": account_id,
            "account_arn": arn,
            "users": auth_details.get('UserDetailList', []),
            "groups": auth_details.get('GroupDetailList', []),
            "roles": auth_details.get('RoleDetailList', []),
            "policies": auth_details.get('Policies', []),
            "managed_policies": managed_policies,
            "password_policy": password_policy,
            "credential_report": credential_report,
            "mfa_devices": mfa_devices,
            "account_summary": account_summary
        }

    except CREDENTIAL_LOAD_ERRORS as e:
        raise InvalidCredentialsError("AWS credentials are missing, incomplete or expired.") from e
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code')
        if code in INVALID_CREDENTIAL_CODES:
            raise InvalidCredentialsError("AWS rejected the credentials (invalid or expired).") from e
        if code in ACCESS_DENIED_CODES:
            raise AccessDeniedError(
                "Access denied. The credentials need the AWS-managed SecurityAudit policy."
            ) from e
        raise
