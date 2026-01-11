"""User model."""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database import Base


class User(Base):
    """User model with intentional vulnerabilities."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)

    # VULNERABILITY: Password stored with weak hashing (for V02)
    password_hash = Column(String(255), nullable=False)

    # VULNERABILITY: Sensitive data exposed (for V03)
    ssn = Column(String(20), nullable=True)  # Social Security Number
    credit_card = Column(String(20), nullable=True)
    secret_note = Column(Text, nullable=True)

    # Role for privilege escalation (V05 - Mass Assignment)
    role = Column(String(20), default="user")  # user, admin, superadmin
    is_active = Column(Boolean, default=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # API key for some endpoints
    api_key = Column(String(64), nullable=True)

    # Relationships
    orders = relationship("Order", back_populates="user")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
