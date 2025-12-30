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
        "description": "A low-privilege identity can assume a high-privilege role to indirectly gain Admin access.",
        "remediation": "Remove sts:AssumeRole permissions from the starting user or add restrictive Conditions to the target role's Trust Policy."
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
    # NEW: Dangerous IAM Actions
    "PRIV_ESC_ACTIONS": {
        "title": "Dangerous IAM Write Actions",
        "severity": "HIGH",
        "category": "Privilege Escalation",
        "description": "User can create or attach policies (iam:CreatePolicy, iam:AttachUserPolicy). This allows them to grant themselves Admin rights.",
        "remediation": "Restrict these actions to specific Administrators only."
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