from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.urls import reverse_lazy
from django.views.generic import CreateView
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_otp.decorators import otp_required
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_ratelimit.decorators import ratelimit
import qrcode
import io
import base64
import logging
from .forms import CustomUserRegistrationForm, CustomLoginForm, TOTPSetupForm, TOTPVerificationForm
from .models import CustomUser, LoginAttempt, UserActivity

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Get the client's IP address from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_login_attempt(request, email, success=False):
    """Log login attempt for security monitoring."""
    try:
        LoginAttempt.objects.create(
            user_email=email,
            ip_address=get_client_ip(request),
            success=success,
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
    except Exception as e:
        logger.error(f"Failed to log login attempt: {e}")


def log_user_activity(user, action, request=None, details=""):
    """Log user activity for audit trail."""
    try:
        UserActivity.objects.create(
            user=user,
            action=action,
            ip_address=get_client_ip(request) if request else None,
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else '',
            details=details
        )
    except Exception as e:
        logger.error(f"Failed to log user activity: {e}")


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def register_view(request):
    """User registration view with approval workflow."""
    if request.method == 'POST':
        form = CustomUserRegistrationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                log_user_activity(
                    user, 
                    'USER_REGISTERED', 
                    request, 
                    f'New user registration from {get_client_ip(request)}'
                )
                messages.success(
                    request, 
                    'Registration successful! Your account is pending approval. '
                    'You will receive an email once your account is approved by an administrator.'
                )
                return redirect('authentication:login')
            except Exception as e:
                logger.error(f"Registration error: {e}")
                messages.error(request, 'Registration failed. Please try again.')
    else:
        form = CustomUserRegistrationForm()
    
    return render(request, 'authentication/register.html', {'form': form})


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def login_view(request):
    """Enhanced login view with MFA support and activity logging."""
    if request.method == 'POST':
        form = CustomLoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            
            try:
                # Update last login IP
                user.last_login_ip = get_client_ip(request)
                user.save(update_fields=['last_login_ip'])
                
                # Log successful login attempt
                log_login_attempt(request, user.email, success=True)
                
                # Check if MFA is enabled for this user
                if user.mfa_enabled and hasattr(user, 'totpdevice_set'):
                    # Check if user has confirmed TOTP device
                    totp_devices = user.totpdevice_set.filter(confirmed=True)
                    if totp_devices.exists():
                        # Store user ID in session for MFA verification
                        request.session['pre_mfa_user_id'] = user.id
                        request.session['pre_mfa_backend'] = user.backend if hasattr(user, 'backend') else 'django.contrib.auth.backends.ModelBackend'
                        return redirect('authentication:mfa_verify')
                
                # Login user directly if no MFA or MFA not properly set up
                login(request, user)
                log_user_activity(user, 'LOGIN_SUCCESS', request, f'Successful login from {get_client_ip(request)}')
                messages.success(request, f'Welcome back, {user.first_name}!')
                return redirect('authentication:dashboard')
                
            except Exception as e:
                logger.error(f"Login process error: {e}")
                messages.error(request, 'Login failed. Please try again.')
        else:
            # Log failed login attempt
            email = request.POST.get('username', '')
            if email:
                log_login_attempt(request, email, success=False)
    else:
        form = CustomLoginForm()
    
    return render(request, 'authentication/login.html', {'form': form})


@login_required
def logout_view(request):
    """Secure logout view with activity logging."""
    user = request.user
    user_name = user.first_name if user.is_authenticated else "User"
    
    # Log logout activity
    if user.is_authenticated:
        log_user_activity(user, 'LOGOUT', request, f'User logged out from {get_client_ip(request)}')
    
    logout(request)
    messages.success(request, f'Goodbye, {user_name}! You have been logged out successfully.')
    return redirect('authentication:login')


@login_required
def dashboard_view(request):
    """User dashboard with security information."""
    user = request.user
    recent_attempts = LoginAttempt.objects.filter(
        user_email=user.email
    ).order_by('-timestamp')[:10]
    
    # Get recent activities for this user
    recent_activities = UserActivity.objects.filter(
        user=user
    ).order_by('-timestamp')[:10]
    
    context = {
        'user': user,
        'recent_attempts': recent_attempts,
        'recent_activities': recent_activities,
    }
    return render(request, 'authentication/dashboard.html', context)


@login_required
def mfa_setup_view(request):
    """Enhanced MFA setup view with better error handling."""
    user = request.user
    
    # Check if user already has MFA enabled
    if user.mfa_enabled:
        # Check if they have a valid confirmed device
        confirmed_devices = TOTPDevice.objects.filter(user=user, confirmed=True)
        if confirmed_devices.exists():
            messages.info(request, 'MFA is already enabled for your account.')
            return redirect('authentication:dashboard')
    
    try:
        # Get or create TOTP device
        device, created = TOTPDevice.objects.get_or_create(
            user=user,
            name='default',
            defaults={'confirmed': False}
        )
        
        # If device exists but is confirmed, create a new one for re-setup
        if not created and device.confirmed:
            device.delete()
            device = TOTPDevice.objects.create(
                user=user,
                name='default',
                confirmed=False
            )
        
        if request.method == 'POST':
            form = TOTPSetupForm(request.POST)
            if form.is_valid():
                token = form.cleaned_data['token']
                try:
                    if device.verify_token(token):
                        device.confirmed = True
                        device.save()
                        user.mfa_enabled = True
                        user.save(update_fields=['mfa_enabled'])
                        
                        # Log MFA enablement
                        log_user_activity(user, 'MFA_ENABLED', request, 'User enabled two-factor authentication')
                        
                        messages.success(request, 'MFA has been successfully enabled for your account!')
                        return redirect('authentication:dashboard')
                    else:
                        messages.error(request, 'Invalid token. Please try again.')
                except Exception as e:
                    logger.error(f"TOTP verification error: {e}")
                    messages.error(request, 'Verification failed. Please try again.')
        else:
            form = TOTPSetupForm()
        
        # Generate QR code
        try:
            qr_code_url = device.config_url
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=5,
            )
            qr.add_data(qr_code_url)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        except Exception as e:
            logger.error(f"QR code generation error: {e}")
            qr_code_data = None
            messages.warning(request, 'QR code generation failed. Please use manual entry.')
        
        context = {
            'form': form,
            'qr_code_data': qr_code_data,
            'manual_key': device.key,
        }
        return render(request, 'authentication/mfa_setup.html', context)
        
    except Exception as e:
        logger.error(f"MFA setup error: {e}")
        messages.error(request, 'MFA setup failed. Please try again later.')
        return redirect('authentication:dashboard')


def mfa_verify_view(request):
    """Enhanced MFA verification view."""
    user_id = request.session.get('pre_mfa_user_id')
    if not user_id:
        messages.error(request, 'Invalid session. Please login again.')
        return redirect('authentication:login')
    
    try:
        user = get_object_or_404(CustomUser, id=user_id)
    except CustomUser.DoesNotExist:
        messages.error(request, 'User not found. Please login again.')
        # Clean up session
        request.session.pop('pre_mfa_user_id', None)
        request.session.pop('pre_mfa_backend', None)
        return redirect('authentication:login')
    
    if request.method == 'POST':
        form = TOTPVerificationForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['otp_token']
            
            try:
                # Get user's TOTP device
                device = TOTPDevice.objects.filter(
                    user=user, 
                    name='default', 
                    confirmed=True
                ).first()
                
                if device and device.verify_token(token):
                    # MFA successful, login user
                    backend = request.session.get('pre_mfa_backend', 'django.contrib.auth.backends.ModelBackend')
                    user.backend = backend
                    login(request, user)
                    
                    # Clean up session
                    request.session.pop('pre_mfa_user_id', None)
                    request.session.pop('pre_mfa_backend', None)
                    
                    # Log successful MFA login
                    log_user_activity(user, 'LOGIN_SUCCESS', request, f'Successful MFA login from {get_client_ip(request)}')
                    
                    messages.success(request, f'Welcome back, {user.first_name}!')
                    return redirect('authentication:dashboard')
                else:
                    messages.error(request, 'Invalid authentication code. Please try again.')
                    
            except TOTPDevice.DoesNotExist:
                messages.error(request, 'MFA device not found. Please contact support.')
                return redirect('authentication:login')
            except Exception as e:
                logger.error(f"MFA verification error: {e}")
                messages.error(request, 'Verification failed. Please try again.')
    else:
        form = TOTPVerificationForm()
    
    return render(request, 'authentication/mfa_verify.html', {'form': form})


@login_required
def mfa_disable_view(request):
    """Disable MFA for user account."""
    user = request.user
    
    if not user.mfa_enabled:
        messages.info(request, 'MFA is not enabled for your account.')
        return redirect('authentication:dashboard')
    
    if request.method == 'POST':
        try:
            # Disable MFA and remove all TOTP devices
            TOTPDevice.objects.filter(user=user).delete()
            user.mfa_enabled = False
            user.save(update_fields=['mfa_enabled'])
            
            # Log MFA disablement
            log_user_activity(user, 'MFA_DISABLED', request, 'User disabled two-factor authentication')
            
            messages.success(request, 'MFA has been disabled for your account.')
            return redirect('authentication:dashboard')
        except Exception as e:
            logger.error(f"MFA disable error: {e}")
            messages.error(request, 'Failed to disable MFA. Please try again.')
    
    return render(request, 'authentication/mfa_disable.html')


@login_required
def profile_view(request):
    """User profile view."""
    return render(request, 'authentication/profile.html', {'user': request.user})