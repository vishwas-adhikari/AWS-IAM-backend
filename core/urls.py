from django.urls import path
from .views import StartScanView, ScanHistoryView, ScanDetailView

urlpatterns = [
    # Path: /api/scan/
    path('scan/', StartScanView.as_view(), name='start-scan'),
    
    # Path: /api/history/
    path('history/', ScanHistoryView.as_view(), name='scan-history'),
    
    # Path: /api/scan/<id>/
    path('scan/<int:pk>/', ScanDetailView.as_view(), name='scan-detail'),
]