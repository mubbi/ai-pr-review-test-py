"""User validation schemas - mixing good and bad practices for testing."""
from marshmallow import Schema, fields, validate, ValidationError
from typing import Dict, Any


class UserCreateSchema(Schema):
    """GOOD PRACTICE: Using Marshmallow for validation with proper constraints."""
    username = fields.Str(required=True, validate=validate.Length(min=3, max=80))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8))
    full_name = fields.Str(validate=validate.Length(max=200))

    class Meta:
        strict = True


class UserUpdateSchema(Schema):
    """GOOD PRACTICE: Separate schema for updates (partial updates allowed)."""
    email = fields.Email()
    full_name = fields.Str(validate=validate.Length(max=200))
    is_active = fields.Bool()

    class Meta:
        strict = True


def validate_user_create(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    GOOD PRACTICE: Validation function with proper error handling.
    
    Args:
        data: User creation data
        
    Returns:
        Validated data
        
    Raises:
        ValidationError: If validation fails
    """
    schema = UserCreateSchema()
    try:
        return schema.load(data)
    except ValidationError as err:
        raise ValidationError(err.messages)


def validate_user_update(data: Dict[str, Any]) -> Dict[str, Any]:
    """GOOD PRACTICE: Validation for updates."""
    schema = UserUpdateSchema()
    try:
        return schema.load(data, partial=True)
    except ValidationError as err:
        raise ValidationError(err.messages)


# BAD PRACTICE – intentional: Manual validation without schema
def validate_user_bad(data: Dict[str, Any]) -> bool:
    """
    BAD PRACTICE – intentional: No proper validation, just basic checks.
    Missing email format validation, length checks, type validation.
    """
    if not data.get('username'):
        return False
    if not data.get('email'):
        return False
    if not data.get('password'):
        return False
    # Missing: email format check, password strength, length validation
    return True


# DRY VIOLATION – intentional: Duplicate validation logic
def validate_email_format(email: str) -> bool:
    """DRY VIOLATION: This validation is duplicated in multiple places."""
    return '@' in email and '.' in email.split('@')[1]


def validate_password_strength(password: str) -> bool:
    """DRY VIOLATION: This logic is repeated elsewhere."""
    return len(password) >= 8
