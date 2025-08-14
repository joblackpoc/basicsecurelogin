from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.utils import timezone
from django_otp.forms import OTPTokenForm
from .models import CustomUser


class CustomUserRegistrationForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address'
        })
    )
    first_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'First Name'
        })
    )
    last_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Last Name'
        })
    )
    phone_number = forms.CharField(
        max_length=15,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Phone Number (optional)'
        })
    )
    
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'phone_number', 'password1', 'password2')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Username'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm Password'
        })
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.phone_number = self.cleaned_data['phone_number']
        user.approval_status = 'pending'
        user.is_active = False  # Will be activated when approved
        if commit:
            user.save()
        return user


class CustomLoginForm(AuthenticationForm):
    username = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email Address',
            'autofocus': True
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        })
    )
    
    def __init__(self, request=None, *args, **kwargs):
        super().__init__(request, *args, **kwargs)
        self.request = request
    
    def clean(self):
        email = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        
        if email and password:
            # Check if user exists
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                raise ValidationError("Invalid email or password.")
            
            # Skip all checks for superusers and staff
            if not (user.is_superuser or user.is_staff):
                # Check if account is locked
                if user.is_locked():
                    raise ValidationError(
                        f"Account is locked until {user.locked_until.strftime('%Y-%m-%d %H:%M:%S')}. "
                        "Please try again later or contact support."
                    )
                
                # Check approval status for regular users only
                if not user.is_approved():
                    if user.is_pending():
                        raise ValidationError("Your account is pending approval. Please wait for admin approval.")
                    elif user.is_rejected():
                        raise ValidationError("Your account has been rejected. Please contact support.")
            
            # Authenticate user
            self.user_cache = authenticate(
                self.request,
                username=email,
                password=password
            )
            
            if self.user_cache is None:
                # Only increment failed attempts for regular users
                if not (user.is_superuser or user.is_staff):
                    user.login_attempts += 1
                    if user.login_attempts >= 5:
                        user.lock_account(duration_minutes=30)
                        user.save()
                        raise ValidationError("Too many failed attempts. Account locked for 30 minutes.")
                    else:
                        user.save()
                raise ValidationError("Invalid email or password.")
            
            # Reset login attempts on successful authentication
            if not (user.is_superuser or user.is_staff):
                user.login_attempts = 0
                user.save()
        
        return self.cleaned_data


class TOTPSetupForm(forms.Form):
    token = forms.CharField(
        max_length=10,  # Allow for formatting with spaces
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter 6-digit code from your authenticator app',
            'autocomplete': 'off',
            'pattern': '[0-9\\s]{6,7}',
            'inputmode': 'numeric'
        }),
        help_text="Enter the 6-digit code from your Google Authenticator app"
    )
    
    def clean_token(self):
        token = self.cleaned_data.get('token')
        if token:
            # Remove all spaces and non-digit characters
            clean_token = ''.join(filter(str.isdigit, token))
            
            # Validate length
            if len(clean_token) != 6:
                raise ValidationError("Token must be exactly 6 digits.")
            
            return clean_token
        return token


class TOTPVerificationForm(forms.Form):
    otp_token = forms.CharField(
        max_length=10,  # Allow for formatting with spaces
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter 6-digit code',
            'autocomplete': 'off',
            'autofocus': True,
            'pattern': '[0-9\\s]{6,7}',
            'inputmode': 'numeric'
        }),
        label="Authentication Code"
    )
    
    def clean_otp_token(self):
        token = self.cleaned_data.get('otp_token')
        if token:
            # Remove all spaces and non-digit characters
            clean_token = ''.join(filter(str.isdigit, token))
            
            # Validate length
            if len(clean_token) != 6:
                raise ValidationError("Token must be exactly 6 digits.")
            
            return clean_token
        return token


class ProfileUpdateForm(forms.ModelForm):
    first_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'First Name'
        })
    )
    last_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Last Name'
        })
    )
    username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Username'
        }),
        help_text="Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only."
    )
    phone_number = forms.CharField(
        max_length=15,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Phone Number (optional)'
        })
    )
    
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'username', 'phone_number']
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username and self.user:
            # Check if username is being changed and if it already exists
            if username != self.user.username:
                if CustomUser.objects.filter(username=username).exists():
                    raise ValidationError("A user with this username already exists.")
        return username
    
    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if phone_number:
            # Basic phone number validation
            import re
            # Remove all non-digit characters for validation
            clean_phone = re.sub(r'\D', '', phone_number)
            if clean_phone and (len(clean_phone) < 10 or len(clean_phone) > 15):
                raise ValidationError("Please enter a valid phone number (10-15 digits).")
        return phone_number
    
    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')
        if first_name:
            # Sanitize and validate first name
            import re
            if not re.match(r'^[a-zA-Z\s\-\'\.]+$', first_name):
                raise ValidationError("First name can only contain letters, spaces, hyphens, apostrophes, and periods.")
            if len(first_name.strip()) < 1:
                raise ValidationError("First name cannot be empty or just spaces.")
        return first_name.strip() if first_name else first_name
    
    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name')
        if last_name:
            # Sanitize and validate last name
            import re
            if not re.match(r'^[a-zA-Z\s\-\'\.]+$', last_name):
                raise ValidationError("Last name can only contain letters, spaces, hyphens, apostrophes, and periods.")
            if len(last_name.strip()) < 1:
                raise ValidationError("Last name cannot be empty or just spaces.")
        return last_name.strip() if last_name else last_name