from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'authentication'

urlpatterns = [
    # User Authentication URLs
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Password Reset URLs
    path('password-reset/', 
         auth_views.PasswordResetView.as_view(
             template_name='authentication/password_reset_form.html',
             email_template_name='authentication/emails/password_reset_email.html',
             subject_template_name='authentication/emails/password_reset_subject.txt',
             success_url='/auth/password-reset/done/'
         ), 
         name='password_reset'),
    path('password-reset/done/', 
         auth_views.PasswordResetDoneView.as_view(
             template_name='authentication/password_reset_done.html'
         ), 
         name='password_reset_done'),
    path('reset/<uidb64>/<token>/', 
         auth_views.PasswordResetConfirmView.as_view(
             template_name='authentication/password_reset_confirm.html',
             success_url='/auth/reset/done/'
         ), 
         name='password_reset_confirm'),
    path('reset/done/', 
         auth_views.PasswordResetCompleteView.as_view(
             template_name='authentication/password_reset_complete.html'
         ), 
         name='password_reset_complete'),
    
    # User Dashboard and Profile URLs
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/update/', views.profile_update_view, name='profile_update'),
    
    # Multi-Factor Authentication URLs
    path('mfa/setup/', views.mfa_setup_view, name='mfa_setup'),
    path('mfa/verify/', views.mfa_verify_view, name='mfa_verify'),
    path('mfa/disable/', views.mfa_disable_view, name='mfa_disable'),
]