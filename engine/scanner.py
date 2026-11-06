from engine import aws_wrapper, iam_normalize, graph_builder, risk_rules,remediation, notifier, policy_engine
from core.models import Scan, Finding, GraphNode, GraphEdge
from django.utils import timezone
from datetime import datetime, timedelta, timezone as dt_timezone

PRIV_ESC_ACTIONS = ['iam:CreatePolicy', 'iam:AttachUserPolicy', 'iam:PutUserPolicy', 'iam:CreateAccessKey']

def run_full_scan(access_key, secret_key, session_token=None):
    # 1. Fetch Data
    data = aws_wrapper.fetch_account_data(access_key, secret_key, session_token)
    
    # 2. Create Scan Record
    scan = Scan.objects.create(
        account_id=data['account_id'],
        account_alias="AWS Account", 
        total_users=len(data['users']),
        total_roles=len(data['roles']),
        total_policies=len(data['policies'])
    )

    findings_list = []
    seen_findings = set()  # (rule_id, node) - one finding per pair
    finding_nodes = []     # (finding, graph node_id) - for colouring the graph

    def add_finding(rule_id, resource_name, node_id=None):
        key = (rule_id, node_id or resource_name)
        if key in seen_findings:
            return
        seen_findings.add(key)
        finding = create_finding(scan, rule_id, resource_name)
        findings_list.append(finding)
        if node_id:
            finding_nodes.append((finding, node_id))

    engine = policy_engine.PolicyEngine(data)

    # --- HELPER: Effective Permission Analysis ---
    def check_principal_risk(principal):
        """Returns the permission rule IDs triggered by a user's or role's effective permissions."""
        # 1. CRITICAL: Admin Access (any policy granting *:*, from any source)
        if engine.is_admin(principal):
            return ["ADMIN_ACCESS"]

        risks_found = []

        # 2. HIGH: Dangerous IAM Write Actions (even when scoped, e.g. to their own user)
        if any(engine.allows_on_any_resource(principal, a) for a in PRIV_ESC_ACTIONS):
            risks_found.append("PRIV_ESC_ACTIONS")

        # 3. HIGH: Service-wide wildcards on all resources
        if engine.service_wildcards(principal):
            risks_found.append("WILDCARD_PERMISSION")

        # 4. MEDIUM: PassRole on any role
        if engine.allows(principal, 'iam:PassRole', '*'):
            risks_found.append("PASSROLE_ANY")

        return risks_found

    # --- HELPER: MFA Status ---
    report_mfa = {
        row['user']: row.get('mfa_active', '').lower() == 'true'
        for row in data.get('credential_report', []) if row.get('user')
    }
    mfa_devices = data.get('mfa_devices', {})

    def user_has_mfa(user_name):
        """True/False from the credential report, else ListMFADevices; None if unknown."""
        if user_name in report_mfa:
            return report_mfa[user_name]
        devices = mfa_devices.get(user_name)
        return None if devices is None else len(devices) > 0

    # --- ANALYSIS PHASE ---

    # A. Check Password Policy
    pp = data.get('password_policy', {})
    # Example check: minimum length < 14
    if not pp or pp.get('MinimumPasswordLength', 0) < 14:
        # Note: We assign this finding to a placeholder "Account-Settings" resource
        add_finding("PASSWORD_POLICY_WEAK", "IAM-Password-Policy")

    # B. Check Users
    for user in data['users']:
        user_name = user['UserName']
        user_arn = engine.get(user).arn

        # Check Keys Age
        for key in user.get('AccessKeyMetadata', []): # Boto3 usually returns this separately, but AuthorizationDetails includes it inside UserDetailList sometimes? 
        # Actually, get_account_authorization_details structure for keys is inside 'UserPolicyList'? No.
        # It's usually in a separate call or part of UserDetail. Let's assume standard UserDetail structure.
        # Standard UserDetail doesn't always have Key creation date easily. 
        # For this MVP, we will rely on 'CreateDate' of the user as a proxy if keys aren't listed, 
        # OR better: Skip key check if data isn't present to avoid crashing.
            pass 

        # 1. Check Permissions (inline + managed + group policies combined)
        all_risks = check_principal_risk(user)
        user_is_admin = "ADMIN_ACCESS" in all_risks

        for risk in all_risks:
            add_finding(risk, user_name, user_arn)

        # 2. Check MFA for Admins (skipped when MFA status couldn't be determined)
        if user_is_admin and user_has_mfa(user_name) is False:
            add_finding("NO_MFA_ADMIN", user_name, user_arn)

        # 3. Check Root Usage (If this user object is actually the root account summary, which sometimes happens in reports)
        if user_name == '<root_account>': 
             # Logic usually requires Credential Report. Skipping for simple MVP to avoid complexity.
             pass

    # C. Check Roles
    for role in data['roles']:
        role_name = role['RoleName']
        role_arn = engine.get(role).arn

        # Trust Policy
        trust_doc = role.get('AssumeRolePolicyDocument', {})
        principals = iam_normalize.get_trust_principals(trust_doc)
        if '*' in principals:
            add_finding("PUBLIC_ASSUME_ROLE", role_name, role_arn)

        # Role Permissions (inline + managed combined)
        for risk in check_principal_risk(role):
            add_finding(risk, role_name, role_arn)

    # D. Build Graph
    graph_engine = graph_builder.IAMGraph()
    graph_engine.build_from_data(data['users'], data['roles'], data['account_id'], engine)
    nodes, edges = graph_engine.get_nodes_and_edges()

    # --- MAP RISKS TO NODES ---
    risk_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    risk_map = {}
    for f, node_id in finding_nodes:
        if risk_rank.get(f.severity, 0) > risk_rank[risk_map.get(node_id, "LOW")]:
            risk_map[node_id] = f.severity

    # --- SAVING ---
    Finding.objects.bulk_create(findings_list)
    
    scan.critical_count = len([f for f in findings_list if f.severity == 'CRITICAL'])
    scan.high_count = len([f for f in findings_list if f.severity == 'HIGH'])
    scan.medium_count = len([f for f in findings_list if f.severity == 'MEDIUM'])
    
     # --- NEW RISK FORMULA (0 = Safe, 100 = Critical) ---
    # Critical = 20 pts, High = 10 pts, Medium = 5 pts
    raw_risk = (scan.critical_count * 20) + (scan.high_count * 10) + (scan.medium_count * 5)
    
    # Cap the score at 100 max
    scan.risk_score = min(100, raw_risk)
    
    scan.save()

    # Save Nodes
    node_objs = []
    for n in nodes:
        # Graph-assigned risk (e.g. the public "*" node) is a floor
        calculated_risk = max(risk_map.get(n['id'], "LOW"), n['risk'], key=lambda r: risk_rank.get(r, 0))
        node_objs.append(GraphNode(
            scan=scan, node_id=n['id'], label=n['label'], type=n['type'], risk_level=calculated_risk
        ))
    GraphNode.objects.bulk_create(node_objs)

    edge_objs = [GraphEdge(scan=scan, source=e['source'], target=e['target'], label=e['label']) for e in edges]
    GraphEdge.objects.bulk_create(edge_objs)

    # --- SEND NOTIFICATION ---
    try:
        notifier.send_telegram_report(scan)
    except Exception as e:
        print(f"Notification Error: {e}")
    return scan

def create_finding(scan_obj, rule_id, resource_name, description=None, details=None):
    rule = risk_rules.RISK_RULES.get(rule_id)
    if not rule: return None
    return Finding(
        scan=scan_obj,
        rule_id=rule_id,
        category=rule['category'],
        title=rule['title'],
        description=description or rule['description'],
        severity=rule['severity'],
        affected_resource=resource_name,
        remediation=rule['remediation'],
        details=details or {}
    )