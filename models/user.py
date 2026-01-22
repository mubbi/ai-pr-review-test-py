"""User model definitions."""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime, Boolean

# Note: In a real app, db would be imported from app.py
# For this test PR, we'll use declarative_base for compatibility
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """User model - GOOD PRACTICE: Clear model definition with proper types."""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)  # GOOD PRACTICE: Storing hash, not plain password
    full_name = Column(String(200))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        """Convert user to dictionary, excluding sensitive fields - GOOD PRACTICE."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
