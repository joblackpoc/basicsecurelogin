# Custom Error Pages

This directory contains custom error page templates for the SecureLogin application.

## Available Error Pages

### 400.html - Bad Request
- **When it's triggered**: Invalid or malformed requests
- **Common causes**: 
  - Invalid form data
  - Missing required parameters
  - CSRF token issues
  - Security validation failures

### 403.html - Forbidden
- **When it's triggered**: Access denied to restricted resources
- **Common causes**:
  - Insufficient user permissions
  - Pending account approval
  - Account restrictions/bans
  - Admin-only resources

### 404.html - Not Found
- **When it's triggered**: Requested resource doesn't exist
- **Common causes**:
  - Incorrect URLs
  - Deleted or moved resources
  - Broken links
  - Typos in URLs

### 500.html - Server Error
- **When it's triggered**: Internal server errors
- **Common causes**:
  - Application bugs
  - Database connection issues
  - Configuration problems
  - Unhandled exceptions

## Features

### Security & Logging
- All error occurrences are logged with:
  - Timestamp
  - IP address
  - User information (if authenticated)
  - Request path
  - Unique error ID for tracking

### User Experience
- Consistent design matching the application theme
- Clear error explanations
- Helpful navigation options
- Context-aware content based on user authentication status

### Responsive Design
- Bootstrap-based responsive layout
- Mobile-friendly design
- Consistent with application styling

## Testing Error Pages

### During Development (DEBUG=True)
Test URLs are available at:
- `/test-errors/400/` - Test 400 error
- `/test-errors/403/` - Test 403 error
- `/test-errors/404/` - Test 404 error
- `/test-errors/500/` - Test 500 error

### Management Command
Run the error page test command:
```bash
python manage.py test_error_pages
python manage.py test_error_pages --error-type 404
```

### Manual Testing
1. **400 Error**: Submit invalid form data
2. **403 Error**: Access admin pages without permissions
3. **404 Error**: Visit any non-existent URL
4. **500 Error**: Force a server error (in test environment)

## Configuration

Error handlers are configured in `settings.py`:
```python
handler400 = 'securelogin.error_views.bad_request_view'
handler403 = 'securelogin.error_views.permission_denied_view'
handler404 = 'securelogin.error_views.page_not_found_view'
handler500 = 'securelogin.error_views.server_error_view'
CSRF_FAILURE_VIEW = 'securelogin.error_views.csrf_failure_view'
```

## Customization

To customize error pages:

1. **Templates**: Edit HTML templates in this directory
2. **Views**: Modify `securelogin/error_views.py`
3. **Styling**: Update CSS in `base.html` or add custom styles

## Security Considerations

- Error pages avoid exposing sensitive information
- All errors are logged for security monitoring
- CSRF failures are handled specially
- Rate limiting may apply to prevent abuse

## Production Notes

- Test URLs are disabled in production (`DEBUG=False`)
- Error logging is configured for monitoring
- Pages are optimized for performance
- Sensitive debug information is hidden