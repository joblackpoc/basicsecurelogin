from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.urls import reverse, path
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db.models import Q, Count
from django.http import HttpResponse
from django.template.response import TemplateResponse
from .models import CustomUser, LoginAttempt, BannedIP, UserActivity
import csv


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = (
        'email', 'username', 'first_name', 'last_name', 
        'approval_status_badge', 'ban_status_badge', 'mfa_enabled', 
        'is_active', 'created_at', 'last_login'
    )
    list_filter = (
        'approval_status', 'is_banned', 'mfa_enabled', 'is_active', 
        'is_staff', 'created_at', 'last_login'
    )
    search_fields = ('email', 'username', 'first_name', 'last_name', 'last_login_ip')
    ordering = ('-created_at',)
    readonly_fields = (
        'created_at', 'updated_at', 'approved_at', 'last_login',
        'banned_at', 'banned_by'
    )
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {
            'fields': ('first_name', 'last_name', 'email', 'phone_number')
        }),
        ('Approval Status', {
            'fields': (
                'approval_status', 'approved_by', 'approved_at'
            )
        }),
        ('Ban Status', {
            'fields': (
                'is_banned', 'banned_at', 'banned_by', 'ban_reason'
            )
        }),
        ('Security', {
            'fields': (
                'mfa_enabled', 'last_login_ip', 'login_attempts', 
                'locked_until'
            )
        }),
        ('Permissions', {
            'fields': (
                'is_active', 'is_staff', 'is_superuser', 
                'groups', 'user_permissions'
            )
        }),
        ('Important dates', {
            'fields': ('last_login', 'date_joined', 'created_at', 'updated_at')
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username', 'email', 'first_name', 'last_name',
                'password1', 'password2', 'approval_status'
            ),
        }),
    )
    
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('pending-users/', self.admin_site.admin_view(self.pending_users_view), 
                 name='auth_customuser_pending'),
            path('security-dashboard/', self.admin_site.admin_view(self.security_dashboard_view), 
                 name='auth_customuser_security'),
            path('export-activities/', self.admin_site.admin_view(self.export_activities), 
                 name='auth_customuser_export_activities'),
        ]
        return custom_urls + urls
    
    def pending_users_view(self, request):
        """Custom view for managing pending users"""
        pending_users = CustomUser.objects.filter(approval_status='pending').order_by('-created_at')
        
        if request.method == 'POST':
            action = request.POST.get('action')
            user_ids = request.POST.getlist('user_ids')
            
            if action == 'approve' and user_ids:
                count = 0
                for user_id in user_ids:
                    try:
                        user = CustomUser.objects.get(id=user_id, approval_status='pending')
                        user.approve_user(request.user)
                        count += 1
                    except CustomUser.DoesNotExist:
                        continue
                
                messages.success(request, f'{count} users have been approved and notified via email.')
            
            elif action == 'reject' and user_ids:
                reason = request.POST.get('rejection_reason', '')
                count = 0
                for user_id in user_ids:
                    try:
                        user = CustomUser.objects.get(id=user_id, approval_status='pending')
                        user.reject_user(request.user, reason)
                        count += 1
                    except CustomUser.DoesNotExist:
                        continue
                
                messages.success(request, f'{count} users have been rejected.')
            
            return redirect('admin:auth_customuser_pending')
        
        context = {
            'pending_users': pending_users,
            'title': 'Pending User Approvals',
            'opts': self.model._meta,
        }
        return TemplateResponse(request, 'admin/authentication/pending_users.html', context)
    
    def security_dashboard_view(self, request):
        """Security dashboard with statistics and recent activities"""
        # Statistics
        stats = {
            'total_users': CustomUser.objects.count(),
            'pending_users': CustomUser.objects.filter(approval_status='pending').count(),
            'banned_users': CustomUser.objects.filter(is_banned=True).count(),
            'banned_ips': BannedIP.objects.filter(is_active=True).count(),
            'failed_logins_today': LoginAttempt.objects.filter(
                success=False,
                timestamp__date=timezone.now().date()
            ).count(),
            'successful_logins_today': LoginAttempt.objects.filter(
                success=True,
                timestamp__date=timezone.now().date()
            ).count(),
        }
        
        # Recent activities
        recent_activities = UserActivity.objects.select_related('user').order_by('-timestamp')[:20]
        
        # Recent failed logins
        recent_failed_logins = LoginAttempt.objects.filter(success=False).order_by('-timestamp')[:10]
        
        # Top IPs with failed attempts
        failed_ips = LoginAttempt.objects.filter(
            success=False,
            timestamp__gte=timezone.now() - timezone.timedelta(days=7)
        ).values('ip_address').annotate(
            count=Count('ip_address')
        ).order_by('-count')[:10]
        
        context = {
            'stats': stats,
            'recent_activities': recent_activities,
            'recent_failed_logins': recent_failed_logins,
            'failed_ips': failed_ips,
            'title': 'Security Dashboard',
            'opts': self.model._meta,
        }
        return TemplateResponse(request, 'admin/authentication/security_dashboard.html', context)
    
    def export_activities(self, request):
        """Export user activities to CSV"""
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="user_activities.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['User Email', 'Action', 'Timestamp', 'IP Address', 'Details'])
        
        activities = UserActivity.objects.select_related('user').order_by('-timestamp')
        for activity in activities:
            writer.writerow([
                activity.user.email,
                activity.get_action_display(),
                activity.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                activity.ip_address or 'N/A',
                activity.details
            ])
        
        return response
    
    def approval_status_badge(self, obj):
        colors = {
            'pending': '#ffc107',
            'approved': '#28a745',
            'rejected': '#dc3545'
        }
        color = colors.get(obj.approval_status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 12px;">{}</span>',
            color,
            obj.get_approval_status_display()
        )
    approval_status_badge.short_description = 'Status'
    approval_status_badge.admin_order_field = 'approval_status'
    
    def ban_status_badge(self, obj):
        if obj.is_banned:
            return format_html(
                '<span style="background-color: #dc3545; color: white; padding: 3px 8px; '
                'border-radius: 3px; font-size: 12px;">BANNED</span>'
            )
        return format_html(
            '<span style="background-color: #28a745; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 12px;">ACTIVE</span>'
        )
    ban_status_badge.short_description = 'Ban Status'
    ban_status_badge.admin_order_field = 'is_banned'
    
    actions = ['approve_users', 'reject_users', 'ban_users', 'unban_users', 'unlock_accounts']
    
    def approve_users(self, request, queryset):
        count = 0
        for user in queryset.filter(approval_status='pending'):
            user.approve_user(request.user)
            count += 1
        self.message_user(
            request, 
            f'{count} users have been approved and notified via email.'
        )
    approve_users.short_description = "Approve selected users"
    
    def reject_users(self, request, queryset):
        count = 0
        for user in queryset.filter(approval_status='pending'):
            user.reject_user(request.user)
            count += 1
        self.message_user(
            request, 
            f'{count} users have been rejected.'
        )
    reject_users.short_description = "Reject selected users"
    
    def ban_users(self, request, queryset):
        count = 0
        for user in queryset.filter(is_banned=False):
            user.ban_user(request.user, "Banned by admin action")
            count += 1
        self.message_user(
            request, 
            f'{count} users have been banned.'
        )
    ban_users.short_description = "Ban selected users"
    
    def unban_users(self, request, queryset):
        count = 0
        for user in queryset.filter(is_banned=True):
            user.unban_user(request.user)
            count += 1
        self.message_user(
            request, 
            f'{count} users have been unbanned.'
        )
    unban_users.short_description = "Unban selected users"
    
    def unlock_accounts(self, request, queryset):
        count = 0
        for user in queryset:
            if user.is_locked():
                user.unlock_account()
                count += 1
        self.message_user(
            request, 
            f'{count} accounts have been unlocked.'
        )
    unlock_accounts.short_description = "Unlock selected accounts"


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = (
        'user_email', 'success_badge', 'ip_address', 
        'timestamp', 'user_agent_short'
    )
    list_filter = ('success', 'timestamp')
    search_fields = ('user_email', 'ip_address')
    readonly_fields = ('user_email', 'ip_address', 'success', 'timestamp', 'user_agent')
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'
    
    actions = ['ban_ip_addresses']
    
    def success_badge(self, obj):
        if obj.success:
            return format_html(
                '<span style="background-color: #28a745; color: white; '
                'padding: 3px 8px; border-radius: 3px; font-size: 12px;">Success</span>'
            )
        else:
            return format_html(
                '<span style="background-color: #dc3545; color: white; '
                'padding: 3px 8px; border-radius: 3px; font-size: 12px;">Failed</span>'
            )
    success_badge.short_description = 'Status'
    success_badge.admin_order_field = 'success'
    
    def user_agent_short(self, obj):
        if obj.user_agent:
            return obj.user_agent[:50] + '...' if len(obj.user_agent) > 50 else obj.user_agent
        return '-'
    user_agent_short.short_description = 'User Agent'
    
    def ban_ip_addresses(self, request, queryset):
        ips = set(queryset.values_list('ip_address', flat=True))
        count = 0
        for ip in ips:
            banned_ip, created = BannedIP.objects.get_or_create(
                ip_address=ip,
                defaults={
                    'reason': 'Banned due to suspicious login attempts',
                    'created_by': request.user,
                    'is_active': True
                }
            )
            if created:
                count += 1
        
        self.message_user(
            request,
            f'{count} IP addresses have been banned.'
        )
    ban_ip_addresses.short_description = "Ban IP addresses from selected attempts"
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(BannedIP)
class BannedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason_short', 'is_active', 'created_at', 'created_by')
    list_filter = ('is_active', 'created_at')
    search_fields = ('ip_address', 'reason')
    readonly_fields = ('created_at', 'created_by')
    ordering = ('-created_at',)
    
    fieldsets = (
        (None, {
            'fields': ('ip_address', 'reason', 'is_active')
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by')
        }),
    )
    
    actions = ['activate_bans', 'deactivate_bans', 'delete_selected']
    
    def reason_short(self, obj):
        return obj.reason[:50] + '...' if len(obj.reason) > 50 else obj.reason
    reason_short.short_description = 'Reason'
    
    def activate_bans(self, request, queryset):
        count = queryset.update(is_active=True)
        self.message_user(
            request,
            f'{count} IP bans have been activated.'
        )
    activate_bans.short_description = "Activate selected IP bans"
    
    def deactivate_bans(self, request, queryset):
        count = queryset.update(is_active=False)
        self.message_user(
            request,
            f'{count} IP bans have been deactivated.'
        )
    deactivate_bans.short_description = "Deactivate selected IP bans"
    
    def save_model(self, request, obj, form, change):
        if not change:  # Only set created_by on new objects
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ('user', 'action_badge', 'timestamp', 'ip_address', 'details_short')
    list_filter = ('action', 'timestamp')
    search_fields = ('user__email', 'user__username', 'ip_address', 'details')
    readonly_fields = ('user', 'action', 'timestamp', 'ip_address', 'user_agent', 'details')
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'
    
    def action_badge(self, obj):
        colors = {
            'LOGIN_SUCCESS': '#28a745',
            'LOGIN_FAILED': '#dc3545',
            'LOGOUT': '#17a2b8',
            'PASSWORD_CHANGE': '#ffc107',
            'MFA_ENABLED': '#28a745',
            'MFA_DISABLED': '#dc3545',
            'USER_BANNED': '#dc3545',
            'USER_UNBANNED': '#28a745',
            'ACCOUNT_LOCKED': '#dc3545',
            'ACCOUNT_UNLOCKED': '#28a745',
        }
        color = colors.get(obj.action, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 12px;">{}</span>',
            color,
            obj.get_action_display()
        )
    action_badge.short_description = 'Action'
    action_badge.admin_order_field = 'action'
    
    def details_short(self, obj):
        return obj.details[:50] + '...' if len(obj.details) > 50 else obj.details
    details_short.short_description = 'Details'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


# Customize admin site header
admin.site.site_header = "SecureLogin Admin Dashboard"
admin.site.site_title = "SecureLogin Admin"
admin.site.index_title = "Welcome to SecureLogin Administration"