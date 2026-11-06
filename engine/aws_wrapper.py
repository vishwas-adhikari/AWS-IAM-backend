import csv
import io
import time

import boto3
from botocore.exceptions import ClientError

# Every call below is covered by the AWS-managed SecurityAudit policy
# (iam:Get*, iam:List*, iam:GenerateCredentialReport, sts:GetCallerIdentity).

CREDENTIAL_REPORT_MAX_ATTEMPTS = 10
CREDENTIAL_REPORT_RETRY_SECONDS = 2


def get_session(access_key, secret_key, session_token=None):
    """Creates a Boto3 session. session_token is required for temporary STS credentials."""
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token or None,
        region_name='us-east-1'  # IAM is global, but boto3 needs a region
    )


def get_iam_client(access_key, secret_key, session_token=None):
    """Creates a Boto3 IAM client using provided credentials."""
    return get_session(access_key, secret_key, session_token).client('iam')


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


def fetch_account_summary(iam):
    """Returns the IAM account summary map (includes AccountMFAEnabled, AccountAccessKeysPresent)."""
    try:
        return iam.get_account_summary().get('SummaryMap', {})
    except ClientError as e:
        print(f"Account summary unavailable: {e}")
        return {}


def fetch_account_data(access_key, secret_key, session_token=None):
    """
    Orchestrates the data collection:
    1. Verifies Identity (GetCallerIdentity)
    2. Downloads IAM snapshot (GetAccountAuthorizationDetails, paginated)
    3. Resolves attached managed policy documents (GetPolicy + GetPolicyVersion)
    4. Fetches Password Policy (Safe Mode)
    5. Fetches Credential Report and Account Summary
    """
    try:
        session = get_session(access_key, secret_key, session_token)

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
            "account_summary": account_summary
        }

    except ClientError as e:
        print(f"AWS Error: {e}")
        raise Exception(f"Failed to connect to AWS: {str(e)}")
    except Exception as e:
        print(f"General Error: {e}")
        raise Exception(f"Scan failed: {str(e)}")
