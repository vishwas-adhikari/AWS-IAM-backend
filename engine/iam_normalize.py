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

TRUST_PRINCIPAL_TYPES = ('AWS', 'Service', 'Federated')

def get_trust_principal_entries(trust_policy):
    """
    Extracts who can assume a role from its Trust Policy.
    Returns a list of (type, value) pairs, type being 'AWS', 'Service' or 'Federated'.
    "Principal": "*" (plain string) is returned as ('AWS', '*').
    """
    statements = normalize_policy_document(trust_policy)
    entries = []

    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue
        principal_block = stmt.get('Principal', {})

        # Handle "Principal": "*" - anyone
        if isinstance(principal_block, str):
            entries.append(('AWS', principal_block))
            continue

        # Handle "AWS"/"Service"/"Federated": "value" or ["value", ...]
        for principal_type in TRUST_PRINCIPAL_TYPES:
            values = principal_block.get(principal_type, [])
            if isinstance(values, str):
                values = [values]
            entries.extend((principal_type, v) for v in values)

    return entries

def get_trust_principals(trust_policy):
    """
    Extracts who can assume a role from its Trust Policy.
    Returns a list of Principals (ARNs, account IDs, Services, Federated providers, or '*').
    """
    return [value for _, value in get_trust_principal_entries(trust_policy)]

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