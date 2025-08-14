from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # User Authentication URLs
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # User Dashboard and Profile URLs
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/update/', views.profile_update_view, name='profile_update'),
    
    # Multi-Factor Authentication URLs
    path('mfa/setup/', views.mfa_setup_view, name='mfa_setup'),
    path('mfa/verify/', views.mfa_verify_view, name='mfa_verify'),
    path('mfa/disable/', views.mfa_disable_view, name='mfa_disable'),
]