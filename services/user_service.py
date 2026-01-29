"""User service layer - business logic with good and bad examples."""
from typing import Optional, Dict, Any, List
from werkzeug.security import generate_password_hash, check_password_hash
from repositories.user_repository import UserRepository, InsecureUserRepository
from models.user import User
from validators.user_validator import (
    validate_user_create, 
    validate_user_update,
    validate_user_bad,
    validate_email_format,
    validate_password_strength
)


class UserService:
    """
    GOOD PRACTICE: Service layer with clear separation of concerns.
    Business logic separated from HTTP and data access layers.
    """
    
    def __init__(self, user_repository: UserRepository):
        """GOOD PRACTICE: Dependency injection."""
        self.repository = user_repository
    
    def create_user(self, user_data: Dict[str, Any]) -> User:
        """
        GOOD PRACTICE: Thin service method delegating to repository.
        Includes proper validation and password hashing.
        """
        # GOOD PRACTICE: Input validation
        validated_data = validate_user_create(user_data)
        
        # GOOD PRACTICE: Check for existing user
        if self.repository.find_by_username(validated_data['username']):
            raise ValueError("Username already exists")
        
        if self.repository.find_by_email(validated_data['email']):
            raise ValueError("Email already exists")
        
        # GOOD PRACTICE: Password hashing before storage
        validated_data['password_hash'] = generate_password_hash(validated_data['password'])
        del validated_data['password']  # Remove plain password
        
        return self.repository.create(validated_data)
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """GOOD PRACTICE: Simple delegation to repository."""
        return self.repository.find_by_id(user_id)
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """GOOD PRACTICE: Clear method naming."""
        return self.repository.find_by_username(username)
    
    def update_user(self, user_id: int, update_data: Dict[str, Any]) -> Optional[User]:
        """
        GOOD PRACTICE: Validation and business logic in service layer.
        """
        user = self.repository.find_by_id(user_id)
        if not user:
            return None
        
        # GOOD PRACTICE: Validate update data
        validated_data = validate_user_update(update_data)
        
        # GOOD PRACTICE: Business rule - email uniqueness check
        if 'email' in validated_data:
            existing = self.repository.find_by_email(validated_data['email'])
            if existing and existing.id != user_id:
                raise ValueError("Email already in use")
        
        return self.repository.update(user, validated_data)
    
    def delete_user(self, user_id: int) -> bool:
        """GOOD PRACTICE: Business logic for deletion."""
        return self.repository.delete(user_id)
    
    def list_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """GOOD PRACTICE: Pagination logic."""
        return self.repository.list_all(limit=limit, offset=offset)
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        GOOD PRACTICE: Authentication logic with password verification.
        Uses secure password hashing comparison.
        """
        user = self.repository.find_by_username(username)
        if not user:
            return None
        
        # GOOD PRACTICE: Secure password verification
        if check_password_hash(user.password_hash, password):
            return user
        
        return None


class BadUserService:
    """
    BAD PRACTICE – intentional: Service mixing multiple responsibilities.
    This class violates Single Responsibility Principle (SOLID violation).
    """
    
    def __init__(self, db_connection):
        """BAD PRACTICE: Direct database connection, no abstraction."""
        self.db = db_connection
        self.insecure_repo = InsecureUserRepository(db_connection)
    
    def handle_user_creation(self, request_data):
        """
        BAD PRACTICE – intentional: Mixing validation, business logic, and data access.
        This method does too many things (SRP violation).
        """
        # BAD PRACTICE: Poor validation
        if not validate_user_bad(request_data):
            return {'error': 'Invalid data'}, 400
        
        # BAD PRACTICE: Business logic mixed with validation
        username = request_data.get('username')
        email = request_data.get('email')
        password = request_data.get('password')
        
        # DRY VIOLATION: Duplicate email validation (also in validators)
        if not validate_email_format(email):
            return {'error': 'Invalid email'}, 400
        
        # DRY VIOLATION: Duplicate password validation
        if not validate_password_strength(password):
            return {'error': 'Weak password'}, 400
        
        # BAD PRACTICE: Direct database access in service
        existing = self.insecure_repo.find_by_username_insecure(username)
        if existing:
            return {'error': 'User exists'}, 409
        
        # SECURITY RISK: Using insecure repository with SQL injection
        self.insecure_repo.create_insecure(username, email, password)
        
        # BAD PRACTICE: Returning HTTP response format from service
        return {'message': 'User created', 'username': username}, 201


# YAGNI VIOLATION – intentional: Over-engineered abstraction not currently used
class UserRepositoryInterface:
    """
    YAGNI VIOLATION – intentional: Abstract interface that is not used anywhere.
    Premature abstraction for future extensibility that doesn't exist yet.
    """
    
    def find_by_id(self, user_id: int):
        raise NotImplementedError
    
    def create(self, user_data: Dict[str, Any]):
        raise NotImplementedError


class CachingUserRepository(UserRepositoryInterface):
    """
    YAGNI VIOLATION – intentional: Caching layer that is never used.
    Over-engineering for performance optimization that isn't needed.
    """
    
    def __init__(self, repository: UserRepository, cache):
        self.repository = repository
        self.cache = cache  # Unused cache implementation
    
    def find_by_id(self, user_id: int):
        # YAGNI: Complex caching logic that isn't needed
        cache_key = f"user:{user_id}"
        cached = self.cache.get(cache_key)  # Never actually used
        if cached:
            return cached
        user = self.repository.find_by_id(user_id)
        self.cache.set(cache_key, user, ttl=3600)  # Unused
        return user
    
    def create(self, user_data: Dict[str, Any]):
        return self.repository.create(user_data)
