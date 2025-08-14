from django.shortcuts import render
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotFound, HttpResponseServerError
from django.utils import timezone
import uuid
import logging

logger = logging.getLogger(__name__)

def bad_request_view(request, exception=None):
    """
    Custom 400 Bad Request error handler.
    """
    # Log the bad request
    logger.warning(f"Bad request from {request.META.get('REMOTE_ADDR', 'Unknown')}: {request.path}")
    
    context = {
        'request_time': timezone.now(),
        'error_id': f"400_{uuid.uuid4().hex[:8].upper()}",
        'request': request,
    }
    
    response = render(request, 'errors/400.html', context)
    response.status_code = 400
    return response

def permission_denied_view(request, exception=None):
    """
    Custom 403 Forbidden error handler.
    """
    # Log the forbidden access attempt
    user_info = f"User: {request.user}" if request.user.is_authenticated else "Anonymous"
    logger.warning(f"Forbidden access attempt - {user_info} - IP: {request.META.get('REMOTE_ADDR', 'Unknown')} - Path: {request.path}")
    
    context = {
        'request_time': timezone.now(),
        'error_id': f"403_{uuid.uuid4().hex[:8].upper()}",
        'request': request,
    }
    
    response = render(request, 'errors/403.html', context)
    response.status_code = 403
    return response

def page_not_found_view(request, exception=None):
    """
    Custom 404 Not Found error handler.
    """
    # Log the 404 error
    logger.info(f"404 Not Found - IP: {request.META.get('REMOTE_ADDR', 'Unknown')} - Path: {request.path}")
    
    context = {
        'request_time': timezone.now(),
        'error_id': f"404_{uuid.uuid4().hex[:8].upper()}",
        'request': request,
    }
    
    response = render(request, 'errors/404.html', context)
    response.status_code = 404
    return response

def server_error_view(request):
    """
    Custom 500 Internal Server Error handler.
    """
    # Log the server error
    error_id = f"500_{uuid.uuid4().hex[:8].upper()}"
    logger.error(f"Server Error {error_id} - IP: {request.META.get('REMOTE_ADDR', 'Unknown')} - Path: {request.path}")
    
    context = {
        'request_time': timezone.now(),
        'error_id': error_id,
        'request': request,
    }
    
    response = render(request, 'errors/500.html', context)
    response.status_code = 500
    return response

def csrf_failure_view(request, reason=""):
    """
    Custom CSRF failure error handler.
    """
    # Log CSRF failure
    logger.warning(f"CSRF failure - IP: {request.META.get('REMOTE_ADDR', 'Unknown')} - Path: {request.path} - Reason: {reason}")
    
    context = {
        'request_time': timezone.now(),
        'error_id': f"CSRF_{uuid.uuid4().hex[:8].upper()}",
        'request': request,
        'reason': reason,
    }
    
    response = render(request, 'errors/csrf.html', context)
    response.status_code = 403
    return response

# Additional utility views for manual error testing (only in DEBUG mode)
def test_error_400(request):
    """Test view for 400 error - only available in DEBUG mode."""
    from django.conf import settings
    if not settings.DEBUG:
        return page_not_found_view(request)
    
    return bad_request_view(request)

def test_error_403(request):
    """Test view for 403 error - only available in DEBUG mode."""
    from django.conf import settings
    if not settings.DEBUG:
        return page_not_found_view(request)
    
    return permission_denied_view(request)

def test_error_404(request):
    """Test view for 404 error - only available in DEBUG mode."""
    from django.conf import settings
    if not settings.DEBUG:
        return page_not_found_view(request)
    
    return page_not_found_view(request)

def test_error_500(request):
    """Test view for 500 error - only available in DEBUG mode."""
    from django.conf import settings
    if not settings.DEBUG:
        return page_not_found_view(request)
    
    # Simulate server error
    raise Exception("Test server error - this is intentional for testing purposes")