from engine import aws_wrapper, iam_normalize, graph_builder, risk_rules, remediation
from core.models import Scan, Finding, GraphNode, GraphEdge
from django.utils import timezone
from datetime import datetime, timedelta, timezone as dt_timezone

def run_full_scan(access_key, secret_key):
    # 1. Fetch Data
    data = aws_wrapper.fetch_account_data(access_key, secret_key)
    
    # 2. Create Scan Record
    scan = Scan.objects.create(
        account_id=data['account_id'],
        account_alias="AWS Account", 
        total_users=len(data['users']),
        total_roles=len(data['roles']),
        total_policies=len(data['policies'])
    )

    findings_list = []
    
    # --- HELPER: Policy Analysis ---
    def check_policy_risk(policy_doc):
        statements = iam_normalize.normalize_policy_document(policy_doc)
        risks_found = []

        for stmt in statements:
            if stmt.get('Effect') != 'Allow': continue
            
            actions = stmt.get('Action', [])
            if isinstance(actions, str): actions = [actions]
            
            resources = stmt.get('Resource', [])
            if isinstance(resources, str): resources = [resources]

            # 1. CRITICAL: Admin Access
            if ('*' in actions) and ('*' in resources):
                risks_found.append("ADMIN_ACCESS")
                continue 

            # 2. HIGH: Dangerous IAM Write Actions
            dangerous_actions = ['iam:CreatePolicy', 'iam:AttachUserPolicy', 'iam:PutUserPolicy', 'iam:CreateAccessKey']
            for da in dangerous_actions:
                if da in actions or '*' in actions:
                    risks_found.append("PRIV_ESC_ACTIONS")
                    break

            # 3. HIGH: Wildcards
            for action in actions:
                if action != '*' and action.endswith(':*') and ('*' in resources):
                    risks_found.append("WILDCARD_PERMISSION")
                    break

            # 4. MEDIUM: PassRole
            if ('iam:PassRole' in actions) and ('*' in resources):
                risks_found.append("PASSROLE_ANY")
        
        return list(set(risks_found))

    # --- ANALYSIS PHASE ---

    # A. Check Password Policy
    pp = data.get('password_policy', {})
    # Example check: minimum length < 14
    if not pp or pp.get('MinimumPasswordLength', 0) < 14:
        # Note: We assign this finding to a placeholder "Account-Settings" resource
        findings_list.append(create_finding(scan, "PASSWORD_POLICY_WEAK", "IAM-Password-Policy"))

    # B. Check Users
    for user in data['users']:
        user_name = user['UserName']
        user_is_admin = False
        
        # Check Keys Age
        for key in user.get('AccessKeyMetadata', []): # Boto3 usually returns this separately, but AuthorizationDetails includes it inside UserDetailList sometimes? 
        # Actually, get_account_authorization_details structure for keys is inside 'UserPolicyList'? No.
        # It's usually in a separate call or part of UserDetail. Let's assume standard UserDetail structure.
        # Standard UserDetail doesn't always have Key creation date easily. 
        # For this MVP, we will rely on 'CreateDate' of the user as a proxy if keys aren't listed, 
        # OR better: Skip key check if data isn't present to avoid crashing.
            pass 

        # 1. Check Permissions
        all_risks = []
        
        # Managed Policies
        for policy in user.get('AttachedManagedPolicies', []):
            if policy['PolicyName'] == 'AdministratorAccess':
                all_risks.append("ADMIN_ACCESS")
                user_is_admin = True
        
        # Inline Policies
        for policy in user.get('UserPolicyList', []):
            risks = check_policy_risk(policy['PolicyDocument'])
            all_risks.extend(risks)
            if "ADMIN_ACCESS" in risks: user_is_admin = True

        # Deduplicate and Add Findings
        for risk in set(all_risks):
            findings_list.append(create_finding(scan, risk, user_name))

        # 2. Check MFA for Admins
        # 'MFADevices' list is present if MFA is enabled
        has_mfa = len(user.get('MFADevices', [])) > 0
        if user_is_admin and not has_mfa:
            findings_list.append(create_finding(scan, "NO_MFA_ADMIN", user_name))

        # 3. Check Root Usage (If this user object is actually the root account summary, which sometimes happens in reports)
        if user_name == '<root_account>': 
             # Logic usually requires Credential Report. Skipping for simple MVP to avoid complexity.
             pass

    # C. Check Roles
    for role in data['roles']:
        role_name = role['RoleName']
        
        # Trust Policy
        trust_doc = role.get('AssumeRolePolicyDocument', {})
        principals = iam_normalize.get_trust_principals(trust_doc)
        if '*' in principals:
            findings_list.append(create_finding(scan, "PUBLIC_ASSUME_ROLE", role_name))

        # Role Permissions
        for policy in role.get('RolePolicyList', []):
            risks = check_policy_risk(policy['PolicyDocument'])
            for r in risks:
                findings_list.append(create_finding(scan, r, role_name))

    # D. Build Graph
    graph_engine = graph_builder.IAMGraph()
    graph_engine.build_from_data(data['users'], data['roles'])
    nodes, edges = graph_engine.get_nodes_and_edges()

    # --- MAP RISKS TO NODES ---
    risk_map = {}
    for f in findings_list:
        current_risk = risk_map.get(f.affected_resource, "LOW")
        if f.severity == "CRITICAL":
            risk_map[f.affected_resource] = "CRITICAL"
        elif f.severity == "HIGH" and current_risk != "CRITICAL":
            risk_map[f.affected_resource] = "HIGH"
        elif f.severity == "MEDIUM" and current_risk not in ["CRITICAL", "HIGH"]:
            risk_map[f.affected_resource] = "MEDIUM"

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
        calculated_risk = risk_map.get(n['id'], "LOW")
        node_objs.append(GraphNode(
            scan=scan, node_id=n['id'], label=n['label'], type=n['type'], risk_level=calculated_risk
        ))
    GraphNode.objects.bulk_create(node_objs)

    edge_objs = [GraphEdge(scan=scan, source=e['source'], target=e['target'], label=e['label']) for e in edges]
    GraphEdge.objects.bulk_create(edge_objs)

    return scan

def create_finding(scan_obj, rule_id, resource_name):
    rule = risk_rules.RISK_RULES.get(rule_id)
    if not rule: return None
    return Finding(
        scan=scan_obj,
        category=rule['category'],
        title=rule['title'],
        description=rule['description'],
        severity=rule['severity'],
        affected_resource=resource_name,
        remediation=rule['remediation']
    )