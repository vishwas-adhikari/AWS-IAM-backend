import logging

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics

# Models & Serializers
from .models import Scan
from .serializers import ScanSerializer

# Import the Logic Engine
from engine import aws_wrapper, scanner

logger = logging.getLogger(__name__)

# Error type -> (HTTP status, message shown to the client). Details only go to the server log.
SCAN_ERROR_RESPONSES = {
    aws_wrapper.ProfileNotFoundError: (status.HTTP_400_BAD_REQUEST, "Unknown AWS profile."),
    aws_wrapper.InvalidCredentialsError: (
        status.HTTP_401_UNAUTHORIZED,
        "The AWS credentials for this profile are invalid or expired.",
    ),
    aws_wrapper.AccessDeniedError: (
        status.HTTP_403_FORBIDDEN,
        "Access denied. The credentials need the AWS-managed SecurityAudit policy.",
    ),
}
GENERIC_SCAN_ERROR = "The scan failed. Check the server logs for details."

# --- NEW: Root View to fix 404 ---
def index(request):
    from django.http import JsonResponse
    return JsonResponse({
        "status": "online",
        "message": "AWS IAM Risk Analyzer Backend is running.",
        "endpoints": {
            "admin": "/admin/",
            "profiles": "/api/profiles/",
            "scan": "/api/scan/",
            "history": "/api/history/"
        }
    })
# ---------------------------------


class ProfileListView(APIView):
    """
    GET /api/profiles/
    Returns the names of the AWS profiles configured on the server. Never credentials.
    """
    def get(self, request):
        try:
            profiles = aws_wrapper.list_profiles()
        except Exception:
            logger.exception("Could not read AWS profiles")
            return Response(
                {"error": "Could not read the AWS configuration on the server."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        return Response({"profiles": profiles})


class StartScanView(APIView):
    """
    POST /api/scan/
    Payload: { "profile": "name" }  - omit or leave empty to use the default credential chain
    Action: Triggers the AWS scan and returns the full report.
    """
    def post(self, request):
        profile = request.data.get('profile') or None

        if profile is not None and not isinstance(profile, str):
            return Response({"error": "'profile' must be a string."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 1. Trigger the logic engine
            # This function will handle Boto3 connection, analysis, and DB saving
            scan_obj = scanner.run_full_scan(profile)

            # 2. Serialize the result (Turn DB object into JSON)
            serializer = ScanSerializer(scan_obj)

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except aws_wrapper.AWSScanError as e:
            http_status, message = SCAN_ERROR_RESPONSES.get(
                type(e), (status.HTTP_500_INTERNAL_SERVER_ERROR, GENERIC_SCAN_ERROR)
            )
            logger.warning("Scan failed for profile %r: %s", profile, e, exc_info=True)
            return Response({"error": message}, status=http_status)

        except Exception:
            logger.exception("Scan failed for profile %r", profile)
            return Response({"error": GENERIC_SCAN_ERROR}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
