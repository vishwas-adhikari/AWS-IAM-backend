from django.contrib import admin
from django.urls import path, include
from core.views import index  # Import the new view

urlpatterns = [
    # The Homepage (Fixes the 404 error)
    path('', index, name='index'),

    # The Admin Dashboard
    path('admin/', admin.site.urls),
    
    # API Routes (Everything in core/urls.py will start with /api/)
    path('api/', include('core.urls')),
]