import json

def normalize_policy_document(policy_doc):
    """
    Standardizes a Policy Document into a predictable format.
    Ensures 'Statement' is always a list.
    """
    if not policy_doc:
        return []
    
    # Handle stringified JSON (common in Trust Policies)
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except:
            return []

    statements = policy_doc.get('Statement', [])
    
    # AWS quirk: If there is only one statement, it returns a dict, not a list.
    if isinstance(statements, dict):
        statements = [statements]
        
    return statements

def get_trust_principals(trust_policy):
    """
    Extracts who can assume a role from its Trust Policy.
    Returns a list of Principals (ARNs, Services, or '*').
    """
    statements = normalize_policy_document(trust_policy)
    principals = []
    
    for stmt in statements:
        if stmt.get('Effect') == 'Allow':
            principal_block = stmt.get('Principal', {})
            
            # Handle "AWS": "arn:..." or "AWS": ["arn:...", "arn:..."]
            if 'AWS' in principal_block:
                aws_princ = principal_block['AWS']
                if isinstance(aws_princ, list):
                    principals.extend(aws_princ)
                else:
                    principals.append(aws_princ)
            
            # Handle Service Principals (e.g., ec2.amazonaws.com)
            if 'Service' in principal_block:
                svc_princ = principal_block['Service']
                if isinstance(svc_princ, list):
                    principals.extend(svc_princ)
                else:
                    principals.append(svc_princ)
                    
    return principals

def is_admin_policy(policy_doc):
    """
    Checks if a policy document grants full Admin access (*:*).
    """
    statements = normalize_policy_document(policy_doc)
    for stmt in statements:
        if stmt.get('Effect') == 'Allow':
            actions = stmt.get('Action', [])
            resources = stmt.get('Resource', [])
            
            # Normalize to lists
            if isinstance(actions, str): actions = [actions]
            if isinstance(resources, str): resources = [resources]
            
            # Check for * on *
            if ('*' in actions) and ('*' in resources):
                return True
    return False