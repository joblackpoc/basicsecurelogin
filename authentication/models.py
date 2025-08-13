from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags


class CustomUser(AbstractUser):
    APPROVAL_STATUS_CHOICES = [
        ('pending', 'Pending Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, blank=True)
    approval_status = models.CharField(
        max_length=20, 
        choices=APPROVAL_STATUS_CHOICES, 
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    approved_by = models.ForeignKey(
        'self', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='approved_users'
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    # Ban system
    is_banned = models.BooleanField(default=False)
    banned_at = models.DateTimeField(null=True, blank=True)
    banned_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='banned_users'
    )
    ban_reason = models.TextField(blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    def __str__(self):
        return f"{self.email} ({self.get_approval_status_display()})"

    def is_approved(self):
        return self.approval_status == 'approved'
    
    def is_pending(self):
        return self.approval_status == 'pending'
    
    def is_rejected(self):
        return self.approval_status == 'rejected'
    
    def approve_user(self, approved_by_user):
        """Approve user and send notification email"""
        self.approval_status = 'approved'
        self.approved_by = approved_by_user
        self.approved_at = timezone.now()
        self.is_active = True
        self.save()
        
        # Send approval email
        self.send_approval_email()
    
    def reject_user(self, approved_by_user, reason=""):
        """Reject user"""
        self.approval_status = 'rejected'
        self.approved_by = approved_by_user
        self.approved_at = timezone.now()
        self.is_active = False
        if reason:
            self.ban_reason = reason
        self.save()
    
    def ban_user(self, banned_by_user, reason=""):
        """Ban user account"""
        self.is_banned = True
        self.banned_at = timezone.now()
        self.banned_by = banned_by_user
        self.ban_reason = reason
        self.is_active = False
        self.save()
        
        # Log the ban
        UserActivity.objects.create(
            user=self,
            action='USER_BANNED',
            ip_address=None,
            details=f'Banned by {banned_by_user.email}. Reason: {reason}'
        )
    
    def unban_user(self, unbanned_by_user):
        """Unban user account"""
        self.is_banned = False
        self.banned_at = None
        self.banned_by = None
        self.ban_reason = ""
        self.is_active = True
        self.save()
        
        # Log the unban
        UserActivity.objects.create(
            user=self,
            action='USER_UNBANNED',
            ip_address=None,
            details=f'Unbanned by {unbanned_by_user.email}'
        )
    
    def send_approval_email(self):
        """Send email notification when user is approved"""
        try:
            subject = 'Account Approved - Welcome to SecureLogin'
            html_message = render_to_string('authentication/emails/approval_email.html', {
                'user': self,
                'login_url': f"{settings.SITE_URL}/auth/login/" if hasattr(settings, 'SITE_URL') else 'http://localhost:8000/auth/login/'
            })
            plain_message = strip_tags(html_message)
            
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[self.email],
                html_message=html_message,
                fail_silently=False,
            )
        except Exception as e:
            # Log the error but don't fail the approval process
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send approval email to {self.email}: {e}")
    
    def is_locked(self):
        if self.locked_until:
            return timezone.now() < self.locked_until
        return False
    
    def lock_account(self, duration_minutes=30):
        self.locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save()
    
    def unlock_account(self):
        self.locked_until = None
        self.login_attempts = 0
        self.save()


class LoginAttempt(models.Model):
    user_email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"{self.user_email} - {status} - {self.timestamp}"


class BannedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Banned IP Address"
        verbose_name_plural = "Banned IP Addresses"
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason[:50]}"


class UserActivity(models.Model):
    ACTION_CHOICES = [
        ('LOGIN_SUCCESS', 'Successful Login'),
        ('LOGIN_FAILED', 'Failed Login'),
        ('LOGOUT', 'Logout'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('MFA_ENABLED', 'MFA Enabled'),
        ('MFA_DISABLED', 'MFA Disabled'),
        ('PROFILE_UPDATE', 'Profile Update'),
        ('USER_APPROVED', 'User Approved'),
        ('USER_REJECTED', 'User Rejected'),
        ('USER_BANNED', 'User Banned'),
        ('USER_UNBANNED', 'User Unbanned'),
        ('ACCOUNT_LOCKED', 'Account Locked'),
        ('ACCOUNT_UNLOCKED', 'Account Unlocked'),
    ]
    
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='activities'
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = "User Activity"
        verbose_name_plural = "User Activities"
    
    def __str__(self):
        return f"{self.user.email} - {self.get_action_display()} - {self.timestamp}"