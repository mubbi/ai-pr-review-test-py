"""Authentication middleware - secure and insecure examples."""
from functools import wraps
from flask import request, jsonify, g
from typing import Callable, Optional, Dict
import jwt
import os


# GOOD PRACTICE: JWT secret from environment variable
JWT_SECRET = os.getenv('JWT_SECRET', 'default-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'


def generate_token(user_id: int, username: str) -> str:
    """
    GOOD PRACTICE: JWT token generation with proper payload.
    """
    payload = {
        'user_id': user_id,
        'username': username,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> Optional[Dict]:
    """
    GOOD PRACTICE: Token verification with error handling.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f: Callable) -> Callable:
    """
    GOOD PRACTICE: Authentication decorator with proper error handling.
    Checks for JWT token and validates it.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'Missing authorization header'}), 401
        
        try:
            # GOOD PRACTICE: Extract token from Bearer format
            token = auth_header.split(' ')[1] if ' ' in auth_header else auth_header
        except IndexError:
            return jsonify({'error': 'Invalid authorization header format'}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # GOOD PRACTICE: Store user info in Flask g for use in route
        g.current_user_id = payload.get('user_id')
        g.current_username = payload.get('username')
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_admin(f: Callable) -> Callable:
    """
    GOOD PRACTICE: Authorization decorator (checks admin role).
    Must be used after require_auth.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # GOOD PRACTICE: Check if user is authenticated first
        if not hasattr(g, 'current_user_id'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # GOOD PRACTICE: In real app, check user role from database
        # For demo, we'll check a header (in production, get from DB)
        is_admin = request.headers.get('X-Admin-User', '').lower() == 'true'
        
        if not is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


# BAD PRACTICE – intentional: No authentication check
def insecure_route(f: Callable) -> Callable:
    """
    SECURITY RISK – intentional: Decorator that does nothing.
    Route using this will have no authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # BAD PRACTICE: No authentication check
        return f(*args, **kwargs)
    
    return decorated_function


# BAD PRACTICE – intentional: Weak authentication
def weak_auth_check(f: Callable) -> Callable:
    """
    SECURITY RISK – intentional: Weak authentication that can be bypassed.
    Only checks for a simple header without validation.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # BAD PRACTICE: Simple header check, no token validation
        user_id = request.headers.get('X-User-Id')
        if not user_id:
            return jsonify({'error': 'Missing user ID'}), 401
        
        # SECURITY RISK: Trusting client-provided user ID without verification
        g.current_user_id = int(user_id)  # No validation, can be spoofed
        
        return f(*args, **kwargs)
    
    return decorated_function
