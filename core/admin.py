from django.contrib import admin
from .models import Scan, Finding, GraphNode, GraphEdge

class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0
    readonly_fields = ('category', 'severity', 'title')

class ScanAdmin(admin.ModelAdmin):
    list_display = ('account_id', 'scan_time', 'risk_score', 'critical_count')
    list_filter = ('scan_time',)
    search_fields = ('account_id', 'account_alias')
    inlines = [FindingInline] # Shows findings directly inside the Scan page

admin.site.register(Scan, ScanAdmin)
admin.site.register(Finding)
admin.site.register(GraphNode)
admin.site.register(GraphEdge)