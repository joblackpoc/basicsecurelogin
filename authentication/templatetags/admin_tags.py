from django import template
from django.db import models

register = template.Library()

@register.filter
def safe_field(obj, field_name):
    """Safely get a field value, return False if field doesn't exist"""
    try:
        return getattr(obj, field_name, False)
    except Exception:
        return False

@register.filter  
def has_field(model_class, field_name):
    """Check if a model has a specific field"""
    try:
        model_class._meta.get_field(field_name)
        return True
    except models.FieldDoesNotExist:
        return False