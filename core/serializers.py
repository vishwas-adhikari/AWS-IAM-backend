from rest_framework import serializers
from .models import Scan, Finding, GraphNode, GraphEdge

class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = ['id', 'category', 'title', 'description', 'severity', 'affected_resource', 'remediation']

class GraphNodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = GraphNode
        fields = ['id', 'node_id', 'label', 'type', 'risk_level']

class GraphEdgeSerializer(serializers.ModelSerializer):
    class Meta:
        model = GraphEdge
        fields = ['id', 'source', 'target', 'label']

class ScanSerializer(serializers.ModelSerializer):
    """
    Main serializer that provides the full report:
    Summary Stats + Findings List + Graph Data
    """
    findings = FindingSerializer(many=True, read_only=True)
    graph_data = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            'id', 'account_id', 'account_alias', 'scan_time', 'risk_score',
            'total_users', 'total_roles', 'total_policies',
            'critical_count', 'high_count', 'medium_count',
            'findings', 'graph_data'
        ]

    def get_graph_data(self, obj):
        """
        Constructs the nodes/edges object structure expected by React Flow
        """
        nodes = GraphNodeSerializer(obj.nodes.all(), many=True).data
        edges = GraphEdgeSerializer(obj.edges.all(), many=True).data
        return {
            "nodes": nodes,
            "edges": edges
        }