from django.db import models

class Scan(models.Model):
    """
    Represents a single execution of the IAM Risk Scanner.
    Stores high-level statistics and metadata.
    """
    account_id = models.CharField(max_length=20, help_text="AWS Account ID")
    account_alias = models.CharField(max_length=100, blank=True, null=True)
    scan_time = models.DateTimeField(auto_now_add=True)
    risk_score = models.IntegerField(default=100, help_text="Calculated Security Score (0-100)")
    
    # Dashboard Counters
    total_users = models.IntegerField(default=0)
    total_roles = models.IntegerField(default=0)
    total_policies = models.IntegerField(default=0)
    
    # Risk Summary
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-scan_time']

    def __str__(self):
        return f"{self.account_id} - {self.scan_time.strftime('%Y-%m-%d %H:%M')}"

class Finding(models.Model):
    """
    Represents a specific security issue detected during a scan.
    """
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='findings')
    category = models.CharField(max_length=100)  # e.g., "Privilege Escalation", "Misconfiguration"
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    affected_resource = models.CharField(max_length=255)  # e.g., "user-dave"
    remediation = models.TextField(help_text="Steps to fix this issue")

    def __str__(self):
        return f"[{self.severity}] {self.title} - {self.affected_resource}"

class GraphNode(models.Model):
    """
    Represents a Node in the visual graph (User, Role, or Policy).
    Compatible with React Flow.
    """
    TYPE_CHOICES = [
        ('USER', 'User'),
        ('ROLE', 'Role'),
        ('GROUP', 'Group'),
        ('POLICY', 'Policy'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='nodes')
    node_id = models.CharField(max_length=255)  # Unique ID for the graph
    label = models.CharField(max_length=255)    # Display name
    type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    risk_level = models.CharField(max_length=10, default="LOW") 
    # Optional: X/Y positions could be stored here if calculated backend-side, 
    # but usually frontend handles layout.

    def __str__(self):
        return f"{self.label} ({self.type})"

class GraphEdge(models.Model):
    """
    Represents a relationship (Edge) between two nodes.
    """
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='edges')
    source = models.CharField(max_length=255) # matches GraphNode.node_id
    target = models.CharField(max_length=255) # matches GraphNode.node_id
    label = models.CharField(max_length=100)  # e.g., "CAN_ASSUME", "HAS_POLICY"

    def __str__(self):
        return f"{self.source} -> {self.target}"