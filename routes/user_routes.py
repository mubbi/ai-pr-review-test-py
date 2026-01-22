"""User routes - demonstrating good and bad practices."""
from flask import Blueprint, request, jsonify, g
from services.user_service import UserService, BadUserService
from repositories.user_repository import UserRepository, InsecureUserRepository
from middleware.auth import require_auth, require_admin, insecure_route, weak_auth_check
from validators.user_validator import validate_user_create, validate_user_update
from models.user import User

user_bp = Blueprint('users', __name__, url_prefix='/api/users')


# GOOD PRACTICE: Thin route handler with dependency injection via Flask g
@user_bp.route('', methods=['POST'])
def create_user():
    """
    GOOD PRACTICE: Thin route handler.
    - Delegates validation to schema
    - Delegates business logic to service
    - Returns appropriate HTTP responses
    """
    try:
        # GOOD PRACTICE: Input validation using schema
        validated_data = validate_user_create(request.json)
        
        # GOOD PRACTICE: Service layer handles business logic
        # GOOD PRACTICE: Dependency injection via Flask g
        user_service = UserService(UserRepository(g.db))
        user = user_service.create_user(validated_data)
        
        # GOOD PRACTICE: Return user data without sensitive fields
        return jsonify(user.to_dict()), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        # GOOD PRACTICE: Don't expose internal errors to client
        return jsonify({'error': 'Internal server error'}), 500


# GOOD PRACTICE: Protected route with authentication
@user_bp.route('/<int:user_id>', methods=['GET'])
@require_auth
def get_user(user_id: int):
    """
    GOOD PRACTICE: Authenticated route with proper authorization check.
    """
    user_service = UserService(UserRepository(g.db))
    user = user_service.get_user_by_id(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # GOOD PRACTICE: Authorization check (users can only view their own profile)
    if g.current_user_id != user_id:
        return jsonify({'error': 'Forbidden'}), 403
    
    return jsonify(user.to_dict()), 200


# GOOD PRACTICE: Admin-only route
@user_bp.route('', methods=['GET'])
@require_auth
@require_admin
def list_users():
    """
    GOOD PRACTICE: Admin route with proper authorization.
    """
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    user_service = UserService(UserRepository(g.db))
    users = user_service.list_users(limit=limit, offset=offset)
    
    return jsonify([user.to_dict() for user in users]), 200


# GOOD PRACTICE: Update route with validation and auth
@user_bp.route('/<int:user_id>', methods=['PATCH'])
@require_auth
def update_user(user_id: int):
    """
    GOOD PRACTICE: Update route with proper validation and authorization.
    """
    try:
        # GOOD PRACTICE: Validate input
        validated_data = validate_user_update(request.json)
        
        user_service = UserService(UserRepository(g.db))
        
        # GOOD PRACTICE: Authorization check
        if g.current_user_id != user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        user = user_service.update_user(user_id, validated_data)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict()), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500


# FAT ROUTE HANDLER – intentional: Anti-pattern demonstration
@user_bp.route('/fat-handler', methods=['POST'])
def fat_route_handler():
    """
    FAT ROUTE HANDLER – intentional: This violates separation of concerns.
    This route handler does everything:
    - Input validation
    - Business logic
    - Database queries
    - Logging
    - Response formatting
    
    BAD PRACTICE: All logic in one place, hard to test and maintain.
    """
    # BAD PRACTICE: Validation directly in route
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or len(username) < 3:
        return jsonify({'error': 'Invalid username'}), 400
    
    if not email or '@' not in email:
        return jsonify({'error': 'Invalid email'}), 400
    
    if not password or len(password) < 8:
        return jsonify({'error': 'Weak password'}), 400
    
    # BAD PRACTICE: Business logic in route
    from werkzeug.security import generate_password_hash
    password_hash = generate_password_hash(password)
    
    # BAD PRACTICE: Direct database access in route
    existing_user = g.db.query(User).filter(User.username == username).first()
    if existing_user:
        return jsonify({'error': 'Username exists'}), 409
    
    existing_email = g.db.query(User).filter(User.email == email).first()
    if existing_email:
        return jsonify({'error': 'Email exists'}), 409
    
    # BAD PRACTICE: Database operation in route
    new_user = User(
        username=username,
        email=email,
        password_hash=password_hash
    )
    g.db.add(new_user)
    g.db.commit()
    g.db.refresh(new_user)
    
    # BAD PRACTICE: Logging in route (should be in service/middleware)
    print(f"User created: {username}")  # Should use proper logger
    
    # BAD PRACTICE: Response formatting in route
    return jsonify({
        'id': new_user.id,
        'username': new_user.username,
        'email': new_user.email,
        'message': 'User created successfully'
    }), 201


# SECURITY RISK – intentional: Insecure route with SQL injection
@user_bp.route('/insecure/<username>', methods=['GET'])
@insecure_route  # BAD PRACTICE: No authentication
def get_user_insecure(username: str):
    """
    SECURITY RISK – intentional: Multiple security vulnerabilities.
    - No authentication
    - SQL injection vulnerability
    - Exposes sensitive data
    """
    # SECURITY RISK: Using insecure repository with SQL injection
    # BAD PRACTICE: Using raw connection instead of session
    insecure_repo = InsecureUserRepository(g.db.bind)
    user = insecure_repo.find_by_username_insecure(username)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # SECURITY RISK: Returning password in response (should never expose)
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'password': user['password']  # SECURITY RISK: Exposing password
    }), 200


# SECURITY RISK – intentional: Route trusting input blindly
@user_bp.route('/trust-input', methods=['POST'])
@weak_auth_check  # BAD PRACTICE: Weak authentication
def trust_user_input():
    """
    SECURITY RISK – intentional: Trusting request.json without validation.
    Missing input validation and using insecure repository.
    """
    # SECURITY RISK: Trusting request.json blindly
    data = request.json  # No validation!
    
    # BAD PRACTICE: Using insecure repository
    insecure_repo = InsecureUserRepository(g.db.bind)
    
    # SECURITY RISK: SQL injection via username and password
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')  # Stored in plain text!
    
    insecure_repo.create_insecure(username, email, password)
    
    # BAD PRACTICE: Exposing internal details in error messages
    try:
        return jsonify({'message': 'User created'}), 201
    except Exception as e:
        # SECURITY RISK: Exposing stack trace to client
        return jsonify({'error': str(e), 'traceback': repr(e.__traceback__)}), 500


# BAD PRACTICE – intentional: Route with poor error handling and hardcoded values
@user_bp.route('/bad-error-handling/<int:user_id>', methods=['DELETE'])
def delete_user_bad(user_id: int):
    """
    BAD PRACTICE – intentional: Poor error handling, no authorization, hardcoded values.
    """
    # BAD PRACTICE: No authentication check
    # BAD PRACTICE: No authorization check (anyone can delete any user)
    # BAD PRACTICE: Hardcoded admin user ID
    admin_user_id = 1  # BAD PRACTICE: Hardcoded value
    
    user = g.db.query(User).filter(User.id == user_id).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # BAD PRACTICE: Hardcoded business rule
    if user_id == admin_user_id:  # BAD PRACTICE: Hardcoded check
        return jsonify({'error': 'Cannot delete admin'}), 400
    
    # BAD PRACTICE: Direct deletion without business logic checks
    g.db.delete(user)
    g.db.commit()
    
    return jsonify({'message': 'User deleted'}), 200


# BAD PRACTICE – intentional: Poor naming and hardcoded values
@user_bp.route('/bad-naming', methods=['POST'])
def x():  # BAD PRACTICE: Poor function naming (should be descriptive like create_user_bad)
    """
    BAD PRACTICE – intentional: Poor variable and function naming.
    Hardcoded values, no validation, mixing concerns.
    """
    # BAD PRACTICE: Poor variable naming
    d = request.json  # BAD PRACTICE: Single letter variable
    u = d.get('username', '')  # BAD PRACTICE: Unclear variable name
    e = d.get('email', '')  # BAD PRACTICE: Unclear variable name
    p = d.get('password', '')  # BAD PRACTICE: Unclear variable name
    
    # BAD PRACTICE: Hardcoded values
    min_len = 3  # BAD PRACTICE: Should be configurable
    max_users = 1000  # BAD PRACTICE: Hardcoded limit
    
    # BAD PRACTICE: No validation
    if len(u) < min_len:
        return jsonify({'msg': 'bad'}), 400  # BAD PRACTICE: Unclear error message
    
    # BAD PRACTICE: Mixing HTTP, DB, and business logic
    from werkzeug.security import generate_password_hash
    ph = generate_password_hash(p)  # BAD PRACTICE: Unclear variable name
    
    # BAD PRACTICE: Direct database access
    count = g.db.query(User).count()
    if count >= max_users:  # BAD PRACTICE: Hardcoded limit
        return jsonify({'msg': 'too many'}), 400
    
    new_user = User(username=u, email=e, password_hash=ph)
    g.db.add(new_user)
    g.db.commit()
    
    return jsonify({'id': new_user.id}), 201
