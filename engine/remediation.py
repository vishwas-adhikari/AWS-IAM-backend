from engine.risk_rules import RISK_RULES

def get_remediation_text(rule_id, entity_name=None):
    """
    Fetches the remediation text for a specific rule.
    Optionally formats it with the entity name for a personalized fix message.
    """
    rule = RISK_RULES.get(rule_id)
    
    if not rule:
        return "Manual investigation required."

    base_fix = rule['remediation']
    
    # Future expansion: Generate CLI commands based on entity_name
    # e.g., "aws iam detach-user-policy --user-name {entity_name} ..."
    
    return base_fix