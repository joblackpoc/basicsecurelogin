from django.core.management.base import BaseCommand
from django.conf import settings
from django.test import RequestFactory
from securelogin.error_views import (
    bad_request_view, 
    permission_denied_view, 
    page_not_found_view, 
    server_error_view
)
from authentication.models import CustomUser

class Command(BaseCommand):
    help = 'Test custom error pages functionality'

    def add_arguments(self, parser):
        parser.add_argument(
            '--error-type',
            type=str,
            choices=['400', '403', '404', '500', 'all'],
            default='all',
            help='Specify which error type to test (default: all)'
        )

    def handle(self, *args, **options):
        if not settings.DEBUG:
            self.stdout.write(
                self.style.WARNING('Error page testing is only available in DEBUG mode.')
            )
            return

        factory = RequestFactory()
        error_type = options['error_type']
        
        self.stdout.write(self.style.SUCCESS('Testing Custom Error Pages'))
        self.stdout.write('=' * 50)

        if error_type in ['400', 'all']:
            self.test_400_error(factory)
        
        if error_type in ['403', 'all']:
            self.test_403_error(factory)
        
        if error_type in ['404', 'all']:
            self.test_404_error(factory)
        
        if error_type in ['500', 'all']:
            self.test_500_error(factory)

        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(self.style.SUCCESS('Error page testing completed!'))
        self.stdout.write(self.style.WARNING('Check your browser at the following test URLs:'))
        self.stdout.write('   • http://localhost:8000/test-errors/400/')
        self.stdout.write('   • http://localhost:8000/test-errors/403/')
        self.stdout.write('   • http://localhost:8000/test-errors/404/')
        self.stdout.write('   • http://localhost:8000/test-errors/500/')

    def test_400_error(self, factory):
        self.stdout.write('\nTesting 400 Bad Request Error:')
        try:
            request = factory.get('/test-path')
            response = bad_request_view(request)
            if response.status_code == 400:
                self.stdout.write(self.style.SUCCESS('  [OK] 400 handler working correctly'))
            else:
                self.stdout.write(self.style.ERROR(f'  [ERROR] Expected 400, got {response.status_code}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  [ERROR] Error testing 400 handler: {e}'))

    def test_403_error(self, factory):
        self.stdout.write('\nTesting 403 Forbidden Error:')
        try:
            request = factory.get('/test-path')
            # Create a mock user for testing
            try:
                user = CustomUser.objects.first()
                if user:
                    request.user = user
                else:
                    request.user = None
            except:
                request.user = None
                
            response = permission_denied_view(request)
            if response.status_code == 403:
                self.stdout.write(self.style.SUCCESS('  [OK] 403 handler working correctly'))
            else:
                self.stdout.write(self.style.ERROR(f'  [ERROR] Expected 403, got {response.status_code}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  [ERROR] Error testing 403 handler: {e}'))

    def test_404_error(self, factory):
        self.stdout.write('\nTesting 404 Not Found Error:')
        try:
            request = factory.get('/nonexistent-path')
            response = page_not_found_view(request)
            if response.status_code == 404:
                self.stdout.write(self.style.SUCCESS('  [OK] 404 handler working correctly'))
            else:
                self.stdout.write(self.style.ERROR(f'  [ERROR] Expected 404, got {response.status_code}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  [ERROR] Error testing 404 handler: {e}'))

    def test_500_error(self, factory):
        self.stdout.write('\nTesting 500 Server Error:')
        try:
            request = factory.get('/test-path')
            response = server_error_view(request)
            if response.status_code == 500:
                self.stdout.write(self.style.SUCCESS('  [OK] 500 handler working correctly'))
            else:
                self.stdout.write(self.style.ERROR(f'  [ERROR] Expected 500, got {response.status_code}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  [ERROR] Error testing 500 handler: {e}'))