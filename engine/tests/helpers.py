"""Builders for fake fetch_account_data() payloads."""

ADMIN_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
ACCOUNT = '111111111111'


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    return dict({"Effect": "Allow", "Action": action, "Resource": resource}, **extra)


def deny(action, resource="*", **extra):
    return dict({"Effect": "Deny", "Action": action, "Resource": resource}, **extra)


def _attached(arns):
    return [{"PolicyName": arn.split('/')[-1], "PolicyArn": arn} for arn in arns]


def _inline(docs):
    return [{"PolicyName": f"inline{i}", "PolicyDocument": d} for i, d in enumerate(docs)]


def user(name, inline=(), managed=(), groups=()):
    return {
        "UserName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "GroupList": list(groups),
        "UserPolicyList": _inline(inline),
        "AttachedManagedPolicies": _attached(managed),
    }


def group(name, inline=(), managed=()):
    return {"GroupName": name, "GroupPolicyList": _inline(inline), "AttachedManagedPolicies": _attached(managed)}


def trust(principal):
    return doc({"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"})


def role(name, inline=(), managed=(), trust_policy=None):
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
        "AssumeRolePolicyDocument": trust_policy or trust({"Service": "ec2.amazonaws.com"}),
        "RolePolicyList": _inline(inline),
        "AttachedManagedPolicies": _attached(managed),
    }


def account_data(users=(), roles=(), groups=(), managed_policies=None, **extra):
    data = {
        "account_id": ACCOUNT,
        "account_arn": f"arn:aws:iam::{ACCOUNT}:user/scanner",
        "users": list(users),
        "groups": list(groups),
        "roles": list(roles),
        "policies": [],
        "managed_policies": managed_policies if managed_policies is not None else {ADMIN_ARN: {"Document": doc(allow("*"))}},
        "password_policy": {"MinimumPasswordLength": 14},
        "credential_report": [],
        "mfa_devices": {},
        "account_summary": {},
    }
    data.update(extra)
    return data
