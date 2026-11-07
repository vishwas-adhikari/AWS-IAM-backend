RISK_RULES = {
    # --- CRITICAL RISKS ---
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
        "description": "A non-admin identity can reach full admin through a chain of IAM permissions (assuming roles, self-granting policies, taking over users, rewriting trust policies or passing roles to compute).",
        "remediation": "Break the chain at its weakest hop: remove or scope the permission on that edge (e.g. restrict sts:AssumeRole, iam:PassRole or IAM write actions to specific ARNs), or add Conditions / a permission boundary."
    },
    # NEW: Root Usage
    "ROOT_USAGE": {
        "title": "Root Account Recently Used",
        "severity": "CRITICAL",
        "category": "Security Hygiene",
        "description": "The Root account credential has been used recently. Root should be locked away and only used for billing/emergency.",
        "remediation": "Stop using Root for daily tasks. Create IAM Users or use Identity Center."
    },

    # --- HIGH RISKS ---
    "WILDCARD_PERMISSION": {
        "title": "Broad Wildcard Permissions",
        "severity": "HIGH",
        "category": "Excessive Permissions",
        "description": "Policy contains broad service wildcards (e.g., 's3:*' or 'ec2:*') on all resources.",
        "remediation": "Scope down permissions. List specific Actions and Resources."
    },
    # NEW: Admin without MFA
    "NO_MFA_ADMIN": {
        "title": "Admin Access without MFA",
        "severity": "HIGH",
        "category": "Security Hygiene",
        "description": "User has Administrator privileges but Multi-Factor Authentication (MFA) is not enabled.",
        "remediation": "Enable MFA immediately. Enforce MFA via IAM Policy Condition 'aws:MultiFactorAuthPresent'."
    },
    # NEW: Old Keys
    "LONG_LIVED_KEYS": {
        "title": "Old Access Keys (>90 Days)",
        "severity": "HIGH",
        "category": "Security Hygiene",
        "description": "Access Key is older than 90 days. Old keys are more likely to be leaked or compromised.",
        "remediation": "Rotate access keys regularly. Deactivate and delete this key."
    },

    # --- MEDIUM RISKS ---
    "PASSROLE_ANY": {
        "title": "PassRole to Any Resource",
        "severity": "MEDIUM",
        "category": "Excessive Permissions",
        "description": "Policy allows 'iam:PassRole' on '*'. Allows passing roles to services to pivot access.",
        "remediation": "Restrict iam:PassRole to specific Role ARNs."
    },
    # NEW: Password Policy
    "PASSWORD_POLICY_WEAK": {
        "title": "Weak Password Policy",
        "severity": "MEDIUM",
        "category": "Misconfiguration",
        "description": "Account password policy does not require enough complexity or rotation.",
        "remediation": "Update IAM Password Policy to require symbols, numbers, and minimum length of 14."
    }
}