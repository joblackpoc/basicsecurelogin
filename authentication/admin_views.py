# Replace authentication/admin_views.py with this after running migration

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
import json

from .models import CustomUser, LoginAttempt, UserActivityLog
from .utils import log_admin_action, send_ban_notification_email, send_mfa_required_email


def is_admin_user(user):
    """Check if user is admin (staff or superuser)"""
    return user.is_authenticated and (user.is_staff or user.is_superuser)


@login_required
@user_passes_test(is_admin_user)
def admin_dashboard_view(request):
    """Admin dashboard with user statistics"""
    
    # Get user statistics
    total_users = CustomUser.objects.filter(is_superuser=False).count()
    pending_users = CustomUser.objects.filter(approval_status='pending').count()
    approved_users = CustomUser.objects.filter(approval_status='approved').count()
    banned_users = CustomUser.objects.filter(is_banned=True).count()
    mfa_enabled_users = CustomUser.objects.filter(mfa_enabled=True).count()
    
    # Recent login attempts
    recent_attempts = LoginAttempt.objects.select_related().order_by('-timestamp')[:10]
    
    # Recent admin actions
    recent_actions = UserActivityLog.objects.select_related(
        'admin_user', 'target_user'
    ).order_by('-timestamp')[:10]
    
    context = {
        'total_users': total_users,
        'pending_users': pending_users,
        'approved_users': approved_users,
        'banned_users': banned_users,
        'mfa_enabled_users': mfa_enabled_users,
        'recent_attempts': recent_attempts,
        'recent_actions': recent_actions,
    }
    
    return render(request, 'authentication/admin/dashboard.html', context)


@login_required
@user_passes_test(is_admin_user)
def user_management_view(request):
    """User management list with filters and pagination"""
    
    # Get filter parameters
    status_filter = request.GET.get('status', 'all')
    search_query = request.GET.get('search', '')
    mfa_filter = request.GET.get('mfa', 'all')
    
    # Build queryset
    users = CustomUser.objects.filter(is_superuser=False).select_related('approved_by', 'banned_by')
    
    # Apply filters
    if status_filter == 'pending':
        users = users.filter(approval_status='pending')
    elif status_filter == 'approved':
        users = users.filter(approval_status='approved')
    elif status_filter == 'rejected':
        users = users.filter(approval_status='rejected')
    elif status_filter == 'banned':
        users = users.filter(is_banned=True)
    elif status_filter == 'active':
        users = users.filter(approval_status='approved', is_banned=False, is_active=True)
    
    if mfa_filter == 'enabled':
        users = users.filter(mfa_enabled=True)
    elif mfa_filter == 'disabled':
        users = users.filter(mfa_enabled=False)
    elif mfa_filter == 'required':
        users = users.filter(mfa_required=True)
    
    if search_query:
        users = users.filter(
            Q(email__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(username__icontains=search_query)
        )
    
    # Order by creation date (newest first)
    users = users.order_by('-created_at')
    
    # Pagination
    paginator = Paginator(users, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'status_filter': status_filter,
        'search_query': search_query,
        'mfa_filter': mfa_filter,
    }
    
    return render(request, 'authentication/admin/user_management.html', context)


@login_required
@user_passes_test(is_admin_user)
def user_detail_view(request, user_id):
    """Detailed view of a specific user"""
    
    user = get_object_or_404(CustomUser, id=user_id, is_superuser=False)
    
    # Get user's login attempts
    login_attempts = LoginAttempt.objects.filter(user_email=user.email).order_by('-timestamp')[:20]
    
    # Get user's activity log
    activity_logs = UserActivityLog.objects.filter(target_user=user).select_related('admin_user').order_by('-timestamp')[:20]
    
    # Get MFA devices
    totp_devices = TOTPDevice.objects.filter(user=user)
    
    context = {
        'target_user': user,
        'login_attempts': login_attempts,
        'activity_logs': activity_logs,
        'totp_devices': totp_devices,
    }
    
    return render(request, 'authentication/admin/user_detail.html', context)


@login_required
@user_passes_test(is_admin_user)
@require_http_methods(["POST"])
def approve_user_view(request, user_id):
    """Approve a pending user"""
    
    user = get_object_or_404(CustomUser, id=user_id, approval_status='pending')
    
    try:
        user.approve_user(request.user)
        log_admin_action(request.user, user, 'approved', request=request)
        
        messages.success(request, f'User {user.email} has been approved and notified via email.')
        
    except Exception as e:
        messages.error(request, f'Failed to approve user: {str(e)}')
    
    return redirect('authentication:admin_user_detail', user_id=user_id)


@login_required
@user_passes_test(is_admin_user)
@require_http_methods(["POST"])
def reject_user_view(request, user_id):
    """Reject a pending user"""
    
    user = get_object_or_404(CustomUser, id=user_id, approval_status='pending')
    reason = request.POST.get('reason', '')
    
    try:
        user.reject_user(request.user)
        log_admin_action(request.user, user, 'rejected', reason=reason, request=request)
        
        messages.success(request, f'User {user.email} has been rejected.')
        
    except Exception as e:
        messages.error(request, f'Failed to reject user: {str(e)}')
    
    return redirect('authentication:admin_user_detail', user_id=user_id)


@login_required
@user_passes_test(is_admin_user)
@require_http_methods(["POST"])
def ban_user_view(request, user_id):
    """Ban a user account"""
    
    user = get_object_or_404(CustomUser, id=user_id, is_superuser=False)
    reason = request.POST.get('reason', '')
    
    if user.is_banned:
        messages.warning(request, f'User {user.email} is already banned.')
        return redirect('authentication:admin_user_detail', user_id=user_id)
    
    try:
        user.ban_user(request.user, reason)
        log_admin_action(request.user, user, 'banned', reason=reason, request=request)
        
        # Send notification email
        send_ban_notification_email(user, reason)
        
        messages.success(request, f'User {user.email} has been banned and notified via email.')
        
    except Exception as e:
        messages.error(request, f'Failed to ban user: {str(e)}')
    
    return redirect('authentication:admin_user_detail', user_id=user_id)


@login_required
@user_passes_test(is_admin_user)
@require_http_methods(["POST"])
def unban_user_view(request, user_id):
    """Unban a user account"""
    
    user = get_object_or_404(CustomUser, id=user_id, is_banned=True)
    
    try:
        user.unban_user()
        log_admin_action(request.user, user, 'unbanned', request=request)
        
        messages.success(request, f'User {user.email} has been unbanned.')
        
    except Exception as e:
        messages.error(request, f'Failed to unban user: {str(e)}')
    
    return redirect('authentication:admin_user_detail', user_id=user_id)


@login_required
@user_passes_test(is_admin_user)
@require_http_methods(["POST"])
def force_mfa_view(request, user_id):
    """Force user to enable MFA"""
    
    user = get_object_or_404(CustomUser, id=user_id, is_superuser=False)
    
    try:
        user.force_mfa_setup()
        log_admin_action(request.user, user, 'mfa_forced', request=request)
        
        # Send notification email
        send_mfa_required_email(user)
        
        messages.success(request, f'MFA requirement has been enforced for {user.email} and they have been notified via email.')
        
    except Exception as e:
        messages.error(request, f'Failed to enforce MFA: {str(e)}')
    
    return redirect('authentication:admin_user_detail', user_id=user_id)


@login_required
@user_passes_test(is_admin_user)
@require_http_methods(["POST"])
def disable_user_mfa_view(request, user_id):
    """Disable MFA for user"""
    
    user = get_object_or_404(CustomUser, id=user_id, is_superuser=False)
    
    try:
        # Remove TOTP devices
        TOTPDevice.objects.filter(user=user).delete()
        
        # Update user MFA settings
        user.mfa_enabled = False
        user.mfa_required = False
        user.save()
        
        log_admin_action(request.user, user, 'mfa_disabled', request=request)
        
        messages.success(request, f'MFA has been disabled for {user.email}.')
        
    except Exception as e:
        messages.error(request, f'Failed to disable MFA: {str(e)}')
    
    return redirect('authentication:admin_user_detail', user_id=user_id)


@login_required
@user_passes_test(is_admin_user)
@require_http_methods(["POST"])
def unlock_user_account_view(request, user_id):
    """Unlock a locked user account"""
    
    user = get_object_or_404(CustomUser, id=user_id, is_superuser=False)
    
    try:
        user.unlock_account()
        log_admin_action(request.user, user, 'account_unlocked', request=request)
        
        messages.success(request, f'Account for {user.email} has been unlocked.')
        
    except Exception as e:
        messages.error(request, f'Failed to unlock account: {str(e)}')
    
    return redirect('authentication:admin_user_detail', user_id=user_id)


@login_required
@user_passes_test(is_admin_user)
def bulk_actions_view(request):
    """Handle bulk actions on multiple users"""
    
    if request.method == 'POST':
        user_ids = request.POST.getlist('user_ids')
        action = request.POST.get('action')
        
        if not user_ids:
            messages.error(request, 'No users selected.')
            return redirect('authentication:admin_user_management')
        
        users = CustomUser.objects.filter(id__in=user_ids, is_superuser=False)
        count = 0
        
        try:
            if action == 'approve':
                for user in users.filter(approval_status='pending'):
                    user.approve_user(request.user)
                    log_admin_action(request.user, user, 'approved', request=request)
                    count += 1
                messages.success(request, f'{count} users have been approved.')
                
            elif action == 'reject':
                for user in users.filter(approval_status='pending'):
                    user.reject_user(request.user)
                    log_admin_action(request.user, user, 'rejected', request=request)
                    count += 1
                messages.success(request, f'{count} users have been rejected.')
                
            elif action == 'ban':
                for user in users.filter(is_banned=False):
                    user.ban_user(request.user)
                    log_admin_action(request.user, user, 'banned', request=request)
                    count += 1
                messages.success(request, f'{count} users have been banned.')
                
            elif action == 'unban':
                for user in users.filter(is_banned=True):
                    user.unban_user()
                    log_admin_action(request.user, user, 'unbanned', request=request)
                    count += 1
                messages.success(request, f'{count} users have been unbanned.')
                
            elif action == 'force_mfa':
                for user in users:
                    user.force_mfa_setup()
                    log_admin_action(request.user, user, 'mfa_forced', request=request)
                    count += 1
                messages.success(request, f'MFA has been enforced for {count} users.')
                
        except Exception as e:
            messages.error(request, f'Bulk action failed: {str(e)}')
    
    return redirect('authentication:admin_user_management')