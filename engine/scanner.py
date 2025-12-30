from engine import aws_wrapper, iam_normalize, graph_builder, risk_rules, remediation
from core.models import Scan, Finding, GraphNode, GraphEdge
from django.utils import timezone

def run_full_scan(access_key, secret_key):
    """
    The Main Entry Point.
    1. Fetches Data from AWS
    2. Analyzes for Risks
    3. Builds Graph
    4. Saves everything to DB
    """
    # 1. Fetch Data
    data = aws_wrapper.fetch_account_data(access_key, secret_key)
    
    # 2. Create Scan Record
    scan = Scan.objects.create(
        account_id=data['account_id'],
        account_alias="AWS Account", # (Can be fetched via aliases API)
        total_users=len(data['users']),
        total_roles=len(data['roles']),
        total_policies=len(data['policies'])
    )

    findings_list = []
    
    # --- ANALYSIS PHASE ---

    # A. Check Users for Admin Access & Issues
    for user in data['users']:
        user_name = user['UserName']
        
        # Check attached managed policies
        for policy in user.get('AttachedManagedPolicies', []):
            if policy['PolicyName'] == 'AdministratorAccess':
                findings_list.append(create_finding(scan, "ADMIN_ACCESS", user_name))

        # Check inline policies (using normalizer)
        for policy in user.get('UserPolicyList', []):
            if iam_normalize.is_admin_policy(policy['PolicyDocument']):
                findings_list.append(create_finding(scan, "ADMIN_ACCESS", user_name))

    # B. Check Roles for Trust Issues
    for role in data['roles']:
        role_name = role['RoleName']
        trust_doc = role.get('AssumeRolePolicyDocument', {})
        
        principals = iam_normalize.get_trust_principals(trust_doc)
        if '*' in principals:
            findings_list.append(create_finding(scan, "PUBLIC_ASSUME_ROLE", role_name))

    # C. Build Graph
    graph_engine = graph_builder.IAMGraph()
    graph_engine.build_from_data(data['users'], data['roles'])
    nodes, edges = graph_engine.get_nodes_and_edges()

    # --- SAVING PHASE ---

    # Bulk create Findings
    Finding.objects.bulk_create(findings_list)
    
    # Update Scan Counts
    scan.critical_count = len([f for f in findings_list if f.severity == 'CRITICAL'])
    scan.high_count = len([f for f in findings_list if f.severity == 'HIGH'])
    scan.medium_count = len([f for f in findings_list if f.severity == 'MEDIUM'])
    
    # Calculate simple score (Starts at 100, minus penalties)
    score = 100 - (scan.critical_count * 15) - (scan.high_count * 5)
    scan.risk_score = max(0, score)
    scan.save()

    # Save Graph Data
    node_objs = [
        GraphNode(scan=scan, node_id=n['id'], label=n['label'], type=n['type'], risk_level=n['risk'])
        for n in nodes
    ]
    GraphNode.objects.bulk_create(node_objs)

    edge_objs = [
        GraphEdge(scan=scan, source=e['source'], target=e['target'], label=e['label'])
        for e in edges
    ]
    GraphEdge.objects.bulk_create(edge_objs)

    return scan

def create_finding(scan_obj, rule_id, resource_name):
    """Helper to instantiate a Finding object from a Rule ID"""
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