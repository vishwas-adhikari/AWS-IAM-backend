"""
RISK_RULES defines the knowledge base for the scanner.
It maps internal Rule IDs to human-readable Titles, Severities, and Fixes.
"""

RISK_RULES = {
    # CRITICAL RISKS
    "ADMIN_ACCESS": {
        "title": "Full Administrator Access",
        "severity": "CRITICAL",
        "category": "Excessive Permissions",
        "description": "Entity has 'AdministratorAccess' policy or effective *:*, granting full control over the account.",
        "remediation": "Detach the AdministratorAccess policy. Replace with least-privilege permissions specific to the user's role."
    },
    "PUBLIC_ASSUME_ROLE": {
        "title": "Publicly Assumable Role",
        "severity": "CRITICAL",
        "category": "Misconfiguration",
        "description": "Trust Policy allows 'Principal': {'AWS': '*'}, enabling any external AWS account to assume this role.",
        "remediation": "Update Trust Policy: Change 'Principal' to a specific AWS Account ID or ARN."
    },
    "PRIVILEGE_ESCALATION": {
        "title": "Privilege Escalation Path",
        "severity": "CRITICAL",
        "category": "Privilege Escalation",
        "description": "A low-privilege identity can assume a high-privilege role to indirectly gain Admin access.",
        "remediation": "Remove sts:AssumeRole permissions from the starting user or add restrictive Conditions to the target role's Trust Policy."
    },

    # HIGH RISKS
    "WILDCARD_PERMISSION": {
        "title": "Broad Wildcard Permissions",
        "severity": "HIGH",
        "category": "Excessive Permissions",
        "description": "Policy contains 'Action': '*' on 'Resource': '*'. This is insecure practice.",
        "remediation": "Scope down permissions. List specific Actions (e.g., s3:ListBucket) and specific Resources."
    },
    "MFA_MISSING": {
        "title": "MFA Not Enabled on Admin",
        "severity": "HIGH",
        "category": "Security Hygiene",
        "description": "User has elevated privileges but does not have MFA enabled.",
        "remediation": "Enforce MFA using the 'aws:MultiFactorAuthPresent' condition in IAM policies."
    },
    "ROOT_USAGE": {
        "title": "Root Account Active",
        "severity": "HIGH",
        "category": "Security Hygiene",
        "description": "The Root account access keys have been used recently. Root should only be used for billing/account recovery.",
        "remediation": "Delete Root access keys. Use IAM Users or Identity Center for daily tasks."
    },

    # MEDIUM RISKS
    "UNUSED_ACCESS_KEY": {
        "title": "Unused Access Key",
        "severity": "MEDIUM",
        "category": "Security Hygiene",
        "description": "Access Key has not been used in >90 days.",
        "remediation": "Deactivate or delete the inactive access key."
    },
    "PASSROLE_ANY": {
        "title": "PassRole to Any Resource",
        "severity": "MEDIUM",
        "category": "Excessive Permissions",
        "description": "Policy allows iam:PassRole on Resource: *. This allows passing roles to services (like EC2) potentially granting their permissions.",
        "remediation": "Restrict iam:PassRole to specific Role ARNs in the Resource field."
    }
}