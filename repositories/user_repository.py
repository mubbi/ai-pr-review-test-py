"""User repository - data access layer with good and bad examples."""
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import text
from models.user import User


class UserRepository:
    """GOOD PRACTICE: Repository pattern with ORM usage."""
    
    def __init__(self, db_session: Session):
        """GOOD PRACTICE: Dependency injection via constructor."""
        self.db = db_session
    
    def find_by_id(self, user_id: int) -> Optional[User]:
        """GOOD PRACTICE: Using ORM with parameter binding (prevents SQL injection)."""
        return self.db.query(User).filter(User.id == user_id).first()
    
    def find_by_username(self, username: str) -> Optional[User]:
        """GOOD PRACTICE: ORM query with parameter binding."""
        return self.db.query(User).filter(User.username == username).first()
    
    def find_by_email(self, email: str) -> Optional[User]:
        """GOOD PRACTICE: ORM query."""
        return self.db.query(User).filter(User.email == email).first()
    
    def create(self, user_data: Dict[str, Any]) -> User:
        """GOOD PRACTICE: Using ORM to create records."""
        user = User(**user_data)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def update(self, user: User, update_data: Dict[str, Any]) -> User:
        """GOOD PRACTICE: ORM-based update."""
        for key, value in update_data.items():
            setattr(user, key, value)
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def delete(self, user_id: int) -> bool:
        """GOOD PRACTICE: ORM-based deletion."""
        user = self.find_by_id(user_id)
        if user:
            self.db.delete(user)
            self.db.commit()
            return True
        return False
    
    def list_all(self, limit: int = 100, offset: int = 0) -> List[User]:
        """GOOD PRACTICE: Paginated query using ORM."""
        return self.db.query(User).limit(limit).offset(offset).all()


class InsecureUserRepository:
    """
    SECURITY RISK – intentional: Raw SQL with string concatenation.
    This class demonstrates SQL injection vulnerabilities.
    """
    
    def __init__(self, db_connection):
        """BAD PRACTICE: Direct database connection instead of session."""
        self.conn = db_connection
    
    def find_by_username_insecure(self, username: str) -> Optional[Dict]:
        """
        SECURITY RISK – intentional: SQL injection vulnerability.
        String concatenation allows SQL injection attacks.
        Example attack: username = "admin' OR '1'='1"
        """
        query = f"SELECT * FROM users WHERE username = '{username}'"
        # BAD PRACTICE: Direct string interpolation in SQL
        result = self.conn.execute(text(query))
        return result.fetchone()
    
    def find_by_id_insecure(self, user_id: str) -> Optional[Dict]:
        """
        SECURITY RISK – intentional: SQL injection via user_id.
        No type checking or parameter binding.
        """
        query = f"SELECT id, username, email, password FROM users WHERE id = {user_id}"
        # BAD PRACTICE: No parameter binding, direct string interpolation
        result = self.conn.execute(text(query))
        return result.fetchone()
    
    def create_insecure(self, username: str, email: str, password: str) -> bool:
        """
        SECURITY RISK – intentional: Multiple vulnerabilities.
        - SQL injection via string concatenation
        - Storing password in plain text (should be hashed)
        """
        query = f"""
            INSERT INTO users (username, email, password) 
            VALUES ('{username}', '{email}', '{password}')
        """
        # BAD PRACTICE: Plain text password storage, SQL injection risk
        self.conn.execute(text(query))
        self.conn.commit()
        return True
