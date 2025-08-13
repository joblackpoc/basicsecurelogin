from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.utils.html import strip_tags
import logging

logger = logging.getLogger(__name__)


def send_approval_email(user):
    """Send email notification when user account is approved"""
    try:
        subject = 'Account Approved - SecureLogin'
        
        # Create HTML email content
        html_message = render_to_string('authentication/emails/account_approved.html', {
            'user': user,
            'login_url': f"{settings.BASE_URL}/auth/login/" if hasattr(settings, 'BASE_URL') else '/auth/login/',
            'site_name': 'SecureLogin',
        })
        
        # Create plain text version
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@securelogin.com'),
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Approval email sent to {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send approval email to {user.email}: {str(e)}")
        return False


def send_ban_notification_email(user, reason=""):
    """Send email notification when user account is banned"""
    try:
        subject = 'Account Suspended - SecureLogin'
        
        html_message = render_to_string('authentication/emails/account_banned.html', {
            'user': user,
            'reason': reason,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@securelogin.com'),
            'site_name': 'SecureLogin',
        })
        
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@securelogin.com'),
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Ban notification email sent to {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send ban notification to {user.email}: {str(e)}")
        return False


def send_mfa_required_email(user):
    """Send email notification when MFA is required by admin"""
    try:
        subject = 'Multi-Factor Authentication Required - SecureLogin'
        
        html_message = render_to_string('authentication/emails/mfa_required.html', {
            'user': user,
            'login_url': f"{settings.BASE_URL}/auth/login/" if hasattr(settings, 'BASE_URL') else '/auth/login/',
            'site_name': 'SecureLogin',
        })
        
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@securelogin.com'),
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"MFA required email sent to {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send MFA required email to {user.email}: {str(e)}")
        return False


def get_client_ip(request):
    """Get the client's IP address from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_admin_action(admin_user, target_user, action, reason="", request=None):
    """Log admin actions for audit trail"""
    from .models import UserActivityLog
    
    try:
        ip_address = get_client_ip(request) if request else None
        
        UserActivityLog.objects.create(
            target_user=target_user,
            admin_user=admin_user,
            action=action,
            reason=reason,
            ip_address=ip_address
        )
        
        logger.info(f"Admin action logged: {admin_user} {action} {target_user}")
        
    except Exception as e:
        logger.error(f"Failed to log admin action: {str(e)}")