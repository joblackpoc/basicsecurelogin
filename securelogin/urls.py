"""
URL configuration for securelogin project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.conf import settings
from django.conf.urls.static import static
from . import error_views

urlpatterns = [
    path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot')),
    path('secure-admin/', admin.site.urls),
    path('auth/', include('authentication.urls')),
    path('', lambda request: redirect('authentication:login'), name='home'),
]

# Error testing URLs (only available in DEBUG mode)
if settings.DEBUG:
    urlpatterns += [
        path('test-errors/400/', error_views.test_error_400, name='test_error_400'),
        path('test-errors/403/', error_views.test_error_403, name='test_error_403'),
        path('test-errors/404/', error_views.test_error_404, name='test_error_404'),
        path('test-errors/500/', error_views.test_error_500, name='test_error_500'),
    ]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
