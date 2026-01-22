"""
SOLID Principles Examples - demonstrating violations and compliance.
This module contains intentional violations and proper implementations.
"""

from typing import List, Dict, Any
from abc import ABC, abstractmethod


# SOLID VIOLATION – intentional: Single Responsibility Principle violation
class UserManager:
    """
    SOLID VIOLATION – intentional: This class violates Single Responsibility Principle.
    It handles:
    1. User validation
    2. User database operations
    3. Email sending
    4. Logging
    5. Report generation
    
    BAD PRACTICE: One class doing too many things.
    """
    
    def __init__(self, db_session, email_service, logger):
        self.db = db_session
        self.email_service = email_service
        self.logger = logger
    
    def validate_user(self, user_data: Dict[str, Any]) -> bool:
        """BAD PRACTICE: Validation mixed with other responsibilities."""
        if not user_data.get('email'):
            return False
        if '@' not in user_data.get('email', ''):
            return False
        return True
    
    def save_user(self, user_data: Dict[str, Any]) -> Dict:
        """BAD PRACTICE: Database operations mixed with other concerns."""
        # Validation (should be separate)
        if not self.validate_user(user_data):
            raise ValueError("Invalid user data")
        
        # Database operation (should be in repository)
        user = self.db.execute(
            f"INSERT INTO users (email, name) VALUES ('{user_data['email']}', '{user_data['name']}')"
        )
        
        # Logging (should be separate)
        self.logger.info(f"User created: {user_data['email']}")
        
        # Email sending (should be separate service)
        self.email_service.send_welcome_email(user_data['email'])
        
        # Report generation (should be separate)
        self.generate_user_report()
        
        return {'id': user.lastrowid, 'email': user_data['email']}
    
    def send_welcome_email(self, email: str):
        """BAD PRACTICE: Email logic in user manager."""
        self.email_service.send(email, "Welcome!")
    
    def generate_user_report(self):
        """BAD PRACTICE: Report generation in user manager."""
        users = self.db.execute("SELECT * FROM users")
        # Generate report...
        pass


# GOOD PRACTICE: SOLID compliance - Single Responsibility Principle
class UserValidator:
    """
    GOOD PRACTICE: Single Responsibility - only handles validation.
    Follows Single Responsibility Principle.
    """
    
    def validate_email(self, email: str) -> bool:
        """GOOD PRACTICE: Focused responsibility."""
        return '@' in email and '.' in email.split('@')[1]
    
    def validate_user_data(self, user_data: Dict[str, Any]) -> bool:
        """GOOD PRACTICE: Validation only."""
        return bool(user_data.get('email') and self.validate_email(user_data['email']))


# GOOD PRACTICE: SOLID compliance - Open/Closed Principle
class NotificationService(ABC):
    """
    GOOD PRACTICE: Abstract base class following Open/Closed Principle.
    Open for extension, closed for modification.
    """
    
    @abstractmethod
    def send(self, recipient: str, message: str) -> bool:
        """GOOD PRACTICE: Abstract method for extension."""
        pass


class EmailNotificationService(NotificationService):
    """
    GOOD PRACTICE: Implementation of abstract class.
    Can extend without modifying base class.
    """
    
    def send(self, recipient: str, message: str) -> bool:
        """GOOD PRACTICE: Concrete implementation."""
        # Email sending logic
        print(f"Sending email to {recipient}: {message}")
        return True


class SMSNotificationService(NotificationService):
    """
    GOOD PRACTICE: Another implementation, demonstrating extensibility.
    Follows Open/Closed Principle.
    """
    
    def send(self, recipient: str, message: str) -> bool:
        """GOOD PRACTICE: Different implementation, same interface."""
        # SMS sending logic
        print(f"Sending SMS to {recipient}: {message}")
        return True


# GOOD PRACTICE: SOLID compliance - Dependency Inversion Principle
class UserServiceGood:
    """
    GOOD PRACTICE: Depends on abstraction (NotificationService interface),
    not concrete implementation. Follows Dependency Inversion Principle.
    """
    
    def __init__(self, notification_service: NotificationService):
        """GOOD PRACTICE: Dependency injection of abstraction."""
        self.notification_service = notification_service
    
    def create_user(self, user_data: Dict[str, Any]) -> Dict:
        """GOOD PRACTICE: Uses injected abstraction."""
        # User creation logic...
        user = {'id': 1, 'email': user_data['email']}
        
        # GOOD PRACTICE: Uses abstraction, not concrete class
        self.notification_service.send(user_data['email'], "Welcome!")
        
        return user


# BAD PRACTICE: Dependency Inversion Principle violation
class UserServiceBad:
    """
    SOLID VIOLATION – intentional: Depends on concrete implementation.
    Violates Dependency Inversion Principle.
    """
    
    def __init__(self):
        """BAD PRACTICE: Creating concrete dependency internally."""
        self.email_service = EmailNotificationService()  # Hard dependency
    
    def create_user(self, user_data: Dict[str, Any]) -> Dict:
        """BAD PRACTICE: Tightly coupled to EmailNotificationService."""
        user = {'id': 1, 'email': user_data['email']}
        self.email_service.send(user_data['email'], "Welcome!")  # Can't swap implementation
        return user
