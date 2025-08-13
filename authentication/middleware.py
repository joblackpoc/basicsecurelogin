from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.template.loader import render_to_string
from .models import CustomUser, BannedIP


def get_client_ip(request):
    """Get the client's IP address from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class IPBanMiddleware(MiddlewareMixin):
    """Middleware to block banned IP addresses"""
    
    def process_request(self, request):
        client_ip = get_client_ip(request)
        
        # Check if IP is banned
        if BannedIP.objects.filter(ip_address=client_ip, is_active=True).exists():
            # Allow access to admin for staff users (in case they ban themselves)
            if request.path.startswith('/admin/') and request.user.is_authenticated and request.user.is_staff:
                return None
            
            # Return forbidden response for banned IPs
            context = {
                'ip_address': client_ip,
                'message': 'Your IP address has been banned due to suspicious activity.'
            }
            html_content = render_to_string('authentication/banned_ip.html', context)
            return HttpResponseForbidden(html_content)
        
        return None


class AccountApprovalMiddleware(MiddlewareMixin):
    """Middleware to handle account approval and ban status"""
    
    def process_request(self, request):
        if request.user.is_authenticated:
            # Skip all checks for staff, superusers, and admin users
            if request.user.is_staff or request.user.is_superuser:
                return None
            
            # Check if user is banned
            if request.user.is_banned:
                messages.error(
                    request,
                    'Your account has been banned. Please contact support for more information.'
                )
                return redirect('authentication:logout')
                
            # Skip approval check for certain URLs
            exempt_urls = [
                reverse('authentication:logout'),
                reverse('admin:index'),
            ]
            
            if request.path not in exempt_urls and not request.path.startswith('/admin/'):
                if not request.user.is_approved():
                    if request.user.is_pending():
                        messages.warning(
                            request, 
                            'Your account is pending approval. Please wait for admin approval or contact support.'
                        )
                    elif request.user.is_rejected():
                        messages.error(
                            request, 
                            'Your account has been rejected. Please contact support for more information.'
                        )
                    return redirect('authentication:logout')
        
        return None


class SecurityHeadersMiddleware(MiddlewareMixin):
    """Middleware to add security headers"""
    
    def process_response(self, request, response):
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "font-src 'self' cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response['Content-Security-Policy'] = csp
        
        return response


class LoginAttemptMiddleware(MiddlewareMixin):
    """Middleware to handle login attempts and account lockouts"""
    
    def process_request(self, request):
        if request.path == reverse('authentication:login') and request.method == 'POST':
            # Check for account lockout before processing login
            email = request.POST.get('username')
            if email:
                try:
                    user = CustomUser.objects.get(email=email)
                    # Skip lockout check for superusers and staff
                    if not (user.is_superuser or user.is_staff):
                        # Check if user is banned
                        if user.is_banned:
                            messages.error(
                                request,
                                'Your account has been banned. Please contact support.'
                            )
                            return redirect('authentication:login')
                        
                        # Check if account is locked
                        if user.is_locked():
                            messages.error(
                                request,
                                f'Account is locked until {user.locked_until.strftime("%Y-%m-%d %H:%M:%S")}. '
                                'Please try again later.'
                            )
                            return redirect('authentication:login')
                except CustomUser.DoesNotExist:
                    pass
        
        return None