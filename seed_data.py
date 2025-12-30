import os
import django
from django.utils import timezone

# 1. Setup Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iam_project.settings')
django.setup()

from core.models import Scan, Finding, GraphNode, GraphEdge

def create_mock_data():
    print("🌱 Seeding Mock Data...")

    # 1. Create a Fake Scan
    scan = Scan.objects.create(
        account_id="123456789012",
        account_alias="demo-production",
        risk_score=65,
        total_users=15,
        total_roles=25,
        total_policies=40,
        critical_count=1,
        high_count=2,
        medium_count=1
    )
    print(f"✅ Created Scan: {scan}")

    # 2. Create Findings (Risks)
    Finding.objects.create(
        scan=scan,
        category="Privilege Escalation",
        title="Indirect Admin Access",
        description="User 'Dave' can assume 'DeploymentRole' which has AdministratorAccess.",
        severity="CRITICAL",
        affected_resource="user-dave",
        remediation="Remove the sts:AssumeRole permission."
    )
    Finding.objects.create(
        scan=scan,
        category="Security Hygiene",
        title="MFA Not Enabled",
        description="User 'Admin-Sarah' has full access but no MFA.",
        severity="HIGH",
        affected_resource="user-sarah",
        remediation="Enforce MFA in IAM policies."
    )
    print("✅ Created Findings")

    # 3. Create Graph Nodes (Visual Map)
    n1 = GraphNode.objects.create(scan=scan, node_id="user-dave", label="Dave", type="USER", risk_level="HIGH")
    n2 = GraphNode.objects.create(scan=scan, node_id="role-deploy", label="DeploymentRole", type="ROLE", risk_level="CRITICAL")
    n3 = GraphNode.objects.create(scan=scan, node_id="policy-admin", label="AdminAccess", type="POLICY", risk_level="CRITICAL")
    print("✅ Created Graph Nodes")

    # 4. Create Graph Edges (Connections)
    GraphEdge.objects.create(scan=scan, source="user-dave", target="role-deploy", label="CAN_ASSUME")
    GraphEdge.objects.create(scan=scan, source="role-deploy", target="policy-admin", label="ATTACHED_TO")
    print("✅ Created Graph Edges")

    print(f"\n🎉 Success! Mock data injected with Scan ID: {scan.id}")

if __name__ == "__main__":
    create_mock_data()