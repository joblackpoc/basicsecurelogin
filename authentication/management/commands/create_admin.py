from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.core.management import CommandError

User = get_user_model()


class Command(BaseCommand):
    help = 'Create an admin user with approved status and superuser privileges'

    def add_arguments(self, parser):
        parser.add_argument('--email', required=True, help='Admin email address')
        parser.add_argument('--username', required=True, help='Admin username')
        parser.add_argument('--password', required=True, help='Admin password')
        parser.add_argument('--first-name', required=False, default='Admin', help='First name')
        parser.add_argument('--last-name', required=False, default='User', help='Last name')

    def handle(self, *args, **options):
        email = options['email']
        username = options['username']
        password = options['password']
        first_name = options['first_name']
        last_name = options['last_name']

        if User.objects.filter(email=email).exists():
            raise CommandError(f'User with email "{email}" already exists.')

        if User.objects.filter(username=username).exists():
            raise CommandError(f'User with username "{username}" already exists.')

        try:
            user = User.objects.create_user(
                email=email,
                username=username,
                password=password,
                first_name=first_name,
                last_name=last_name,
                approval_status='approved',  # Automatically approved
                is_staff=True,
                is_superuser=True,
                is_active=True
            )

            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully created admin user: {email}\n'
                    f'Username: {username}\n'
                    f'Status: Approved\n'
                    f'Superuser: Yes\n'
                    f'Staff: Yes'
                )
            )
        except Exception as e:
            raise CommandError(f'Failed to create admin user: {str(e)}')