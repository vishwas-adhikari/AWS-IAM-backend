"""
Effective-permission evaluation for IAM users and roles.

Each principal's permissions are the union of:
  - its inline policies
  - its attached managed policies (customer- and AWS-managed)
  - for users: the inline + attached policies of every group it belongs to

Evaluation rules (identity policies only - SCPs, permission boundaries and
resource policies are out of scope):
  - Actions match case-insensitively with IAM wildcards ("*", "iam:*", "iam:Attach*").
    Resources (ARNs) match case-sensitively.
  - NotAction / NotResource are supported.
  - An explicit Deny overrides any Allow.
  - Conditions are treated conservatively for a risk scanner: a conditional Allow
    still counts as granted, a conditional Deny is NOT trusted to block access.
  - is_admin() also counts a principal as admin despite a narrow Deny it could
    remove itself (see is_admin).

Queries may themselves contain wildcards. allows(p, "*", "*") asks "can p do every
action on every resource", so an Allow must fully cover the query and any Deny
that overlaps any part of it blocks it.
"""
from fnmatch import fnmatchcase
from functools import lru_cache

from engine import iam_normalize

ADMIN_POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
ADMIN_STATEMENT = {"Effect": "Allow", "Action": "*", "Resource": "*"}

# IAM write actions a principal needs to strip a Deny out of its own policies.
DENY_REMOVAL_ACTIONS = [
    'iam:DetachUserPolicy', 'iam:DetachRolePolicy',
    'iam:DeleteUserPolicy', 'iam:DeleteRolePolicy',
    'iam:PutUserPolicy', 'iam:PutRolePolicy',
    'iam:CreatePolicyVersion',
]
# Any IAM resource, per partition - a Deny scoped to e.g. an S3 bucket can't block these.
IAM_RESOURCES = ['arn:aws:iam::*', 'arn:aws-cn:iam::*', 'arn:aws-us-gov:iam::*']


# --- Wildcard pattern helpers ---

def _has_wildcard(value):
    return '*' in value or '?' in value


@lru_cache(maxsize=None)
def _covers(pattern, query):
    """True if every string matched by `query` is also matched by `pattern`."""
    if not _has_wildcard(query):
        return fnmatchcase(query, pattern)

    def walk(i, j):
        if i == len(pattern):
            return j == len(query)
        if pattern[i] == '*':
            return walk(i + 1, j) or (j < len(query) and walk(i, j + 1))
        if j == len(query) or query[j] == '*':
            return False
        if query[j] == '?':
            return pattern[i] == '?' and walk(i + 1, j + 1)
        return pattern[i] in ('?', query[j]) and walk(i + 1, j + 1)

    return walk(0, 0)


@lru_cache(maxsize=None)
def _overlaps(pattern, query):
    """True if at least one string is matched by both `pattern` and `query`."""
    if not _has_wildcard(query):
        return fnmatchcase(query, pattern)

    def walk(i, j):
        if i == len(pattern) and j == len(query):
            return True
        if i < len(pattern) and pattern[i] == '*':
            return walk(i + 1, j) or (j < len(query) and walk(i, j + 1))
        if j < len(query) and query[j] == '*':
            return walk(i, j + 1) or (i < len(pattern) and walk(i + 1, j))
        if i == len(pattern) or j == len(query):
            return False
        return (pattern[i] == '?' or query[j] == '?' or pattern[i] == query[j]) and walk(i + 1, j + 1)

    return walk(0, 0)


def _as_list(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


# --- Statement matching ---

class Statement:
    """A single normalized policy statement, tagged with the policy it came from."""

    def __init__(self, raw, source):
        self.effect = raw.get('Effect')
        self.source = source
        self.has_condition = bool(raw.get('Condition'))

        self.actions = [a.lower() for a in _as_list(raw.get('Action'))]
        self.not_actions = [a.lower() for a in _as_list(raw.get('NotAction'))]
        self.uses_not_action = 'NotAction' in raw

        self.resources = _as_list(raw.get('Resource'))
        self.not_resources = _as_list(raw.get('NotResource'))
        self.uses_not_resource = 'NotResource' in raw

    def _action_covers(self, action):
        if self.uses_not_action:
            return not any(_overlaps(n, action) for n in self.not_actions)
        return any(_covers(p, action) for p in self.actions)

    def _action_overlaps(self, action):
        if self.uses_not_action:
            return not any(_covers(n, action) for n in self.not_actions)
        return any(_overlaps(p, action) for p in self.actions)

    def _resource_covers(self, resource):
        if self.uses_not_resource:
            return not any(_overlaps(n, resource) for n in self.not_resources)
        return any(_covers(p, resource) for p in self.resources)

    def _resource_overlaps(self, resource):
        if self.uses_not_resource:
            return not any(_covers(n, resource) for n in self.not_resources)
        return any(_overlaps(p, resource) for p in self.resources)

    def grants(self, action, resource):
        """Allow statement that grants all of action x resource."""
        return (self.effect == 'Allow'
                and self._action_covers(action)
                and self._resource_covers(resource))

    def grants_some(self, action):
        """Allow statement that grants all of `action` on at least one resource."""
        return (self.effect == 'Allow'
                and self._action_covers(action)
                and (self.uses_not_resource or bool(self.resources)))

    def blocks(self, action, resource):
        """Unconditional Deny statement that hits any part of action x resource."""
        return (self.effect == 'Deny'
                and not self.has_condition
                and self._action_overlaps(action)
                and self._resource_overlaps(resource))

    def blocks_everywhere(self, action):
        """Unconditional Deny statement that blocks all of `action` on every resource."""
        return (self.effect == 'Deny'
                and not self.has_condition
                and self._action_covers(action)
                and self._resource_covers("*"))


def parse_document(policy_doc, source):
    return [Statement(s, source) for s in iam_normalize.normalize_policy_document(policy_doc)]


# --- Principals ---

class Principal:
    """A user or role together with its full effective statement list."""

    def __init__(self, kind, name, arn, statements, unresolved_policies):
        self.kind = kind  # 'user' | 'role' | 'group'
        self.attached_policy_arns = []  # managed policies, incl. those inherited from groups
        self.name = name
        self.arn = arn
        self.statements = statements
        self.unresolved_policies = unresolved_policies

    def __repr__(self):
        return f"<Principal {self.kind}:{self.name}>"


class PolicyEngine:
    """
    Built from the dict returned by aws_wrapper.fetch_account_data().
    Lookups accept a Principal, a UserDetail/RoleDetail dict, or an ARN.
    """

    def __init__(self, data):
        self.managed_policies = data.get('managed_policies', {})
        self.groups = {g['GroupName']: g for g in data.get('groups', [])}
        self.principals = {}  # arn -> Principal
        self._by_name = {}    # (kind, name) -> Principal

        for user in data.get('users', []):
            self._add(self._build_user(user))
        for role in data.get('roles', []):
            self._add(self._build_role(role))

        # Groups aren't principals, but evaluating them answers "what does joining this group grant?"
        self.group_principals = {name: self._build_group(g) for name, g in self.groups.items()}

    def _add(self, principal):
        self.principals[principal.arn] = principal
        self._by_name[(principal.kind, principal.name)] = principal

    # -- building --

    def _managed_statements(self, attached, unresolved):
        statements = []
        for policy in attached:
            arn, name = policy['PolicyArn'], policy['PolicyName']
            resolved = self.managed_policies.get(arn)
            if resolved:
                statements.extend(parse_document(resolved.get('Document'), f"managed:{name}"))
            elif arn == ADMIN_POLICY_ARN:
                # Document couldn't be fetched, but its contents are well known.
                statements.append(Statement(ADMIN_STATEMENT, f"managed:{name}"))
            else:
                unresolved.append(arn)
        return statements

    @staticmethod
    def _inline_statements(policy_list, prefix):
        statements = []
        for policy in policy_list:
            statements.extend(parse_document(policy.get('PolicyDocument'), f"{prefix}:{policy.get('PolicyName')}"))
        return statements

    def _build_user(self, user):
        unresolved = []
        attached = list(user.get('AttachedManagedPolicies', []))
        statements = self._inline_statements(user.get('UserPolicyList', []), "inline")
        statements += self._managed_statements(user.get('AttachedManagedPolicies', []), unresolved)

        for group_name in user.get('GroupList', []):
            group = self.groups.get(group_name)
            if not group:
                continue
            attached += group.get('AttachedManagedPolicies', [])
            statements += self._inline_statements(group.get('GroupPolicyList', []), f"group:{group_name}:inline")
            statements += self._managed_statements(group.get('AttachedManagedPolicies', []), unresolved)

        p = Principal('user', user['UserName'], user.get('Arn', f"user/{user['UserName']}"), statements, unresolved)
        p.attached_policy_arns = sorted({a['PolicyArn'] for a in attached})
        return p

    def _build_role(self, role):
        unresolved = []
        statements = self._inline_statements(role.get('RolePolicyList', []), "inline")
        statements += self._managed_statements(role.get('AttachedManagedPolicies', []), unresolved)
        p = Principal('role', role['RoleName'], role.get('Arn', f"role/{role['RoleName']}"), statements, unresolved)
        p.attached_policy_arns = sorted({a['PolicyArn'] for a in role.get('AttachedManagedPolicies', [])})
        return p

    def _build_group(self, group):
        unresolved = []
        statements = self._inline_statements(group.get('GroupPolicyList', []), "inline")
        statements += self._managed_statements(group.get('AttachedManagedPolicies', []), unresolved)
        p = Principal('group', group['GroupName'], group.get('Arn', f"group/{group['GroupName']}"), statements, unresolved)
        p.attached_policy_arns = sorted({a['PolicyArn'] for a in group.get('AttachedManagedPolicies', [])})
        return p

    # -- lookup --

    def get(self, principal):
        if isinstance(principal, Principal):
            return principal
        if isinstance(principal, dict):
            if 'UserName' in principal:
                return self._by_name[('user', principal['UserName'])]
            return self._by_name[('role', principal['RoleName'])]
        return self.principals[principal]

    # -- queries --

    def allows(self, principal, action, resource="*"):
        """Can `principal` perform all of `action` on all of `resource`?"""
        p = self.get(principal)
        action = action.lower()
        if any(s.blocks(action, resource) for s in p.statements):
            return False
        return any(s.grants(action, resource) for s in p.statements)

    def allows_on_any_resource(self, principal, action):
        """Can `principal` perform `action` on at least one resource (e.g. its own user ARN)?"""
        p = self.get(principal)
        action = action.lower()
        if any(s.blocks_everywhere(action) for s in p.statements):
            return False
        return any(s.grants_some(action) for s in p.statements)

    def is_admin(self, principal):
        """
        Full access: every action on every resource.

        A narrow Deny (e.g. s3:DeleteBucket) doesn't remove admin status from a
        principal with an Allow *:* (conditional or not, as everywhere else), because they can just remove the
        Deny. They're only non-admin if a Deny blocks the IAM write actions needed to
        do that (a full Deny * included).
        """
        p = self.get(principal)
        if self.allows(p, "*", "*"):
            return True
        if not any(s.grants("*", "*") for s in p.statements):
            return False
        return not any(
            s.blocks(action.lower(), resource)
            for action in DENY_REMOVAL_ACTIONS
            for resource in IAM_RESOURCES
            for s in p.statements
        )

    def service_wildcards(self, principal):
        """Service-wide grants like "s3:*" on all resources that survive Deny evaluation."""
        p = self.get(principal)
        found = set()
        for s in p.statements:
            if s.effect != 'Allow' or s.uses_not_action:
                continue
            for action in s.actions:
                if action != '*' and action.endswith(':*') and self.allows(p, action, "*"):
                    found.add(action)
        return sorted(found)
