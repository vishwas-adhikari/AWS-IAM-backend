from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics

# Models & Serializers
from .models import Scan
from .serializers import ScanSerializer

# Import the Logic Engine (We will build this next)
from engine import scanner

# Import the Logic Engine
from engine import scanner

# --- NEW: Root View to fix 404 ---
def index(request):
    from django.http import JsonResponse
    return JsonResponse({
        "status": "online", 
        "message": "AWS IAM Risk Analyzer Backend is running.", 
        "endpoints": {
            "admin": "/admin/",
            "scan": "/api/scan/",
            "history": "/api/history/"
        }
    })
# ---------------------------------


class StartScanView(APIView):
    """
    POST /api/scan/
    Payload: { "access_key": "...", "secret_key": "..." }
    Action: Triggers the AWS scan and returns the full report.
    """
    def post(self, request):
        access_key = request.data.get('access_key')
        secret_key = request.data.get('secret_key')

        if not access_key or not secret_key:
            return Response(
                {"error": "AWS Credentials (access_key, secret_key) are required."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # 1. Trigger the logic engine
            # This function will handle Boto3 connection, analysis, and DB saving
            scan_obj = scanner.run_full_scan(access_key, secret_key)
            
            # 2. Serialize the result (Turn DB object into JSON)
            serializer = ScanSerializer(scan_obj)
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Catch invalid keys or AWS errors
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ScanHistoryView(generics.ListAPIView):
    """
    GET /api/history/
    Returns a list of all past scans (summary only).
    """
    queryset = Scan.objects.all().order_by('-scan_time')
    serializer_class = ScanSerializer

class ScanDetailView(generics.RetrieveAPIView):
    """
    GET /api/scan/<id>/
    Returns full details for a specific historical scan.
    """
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer