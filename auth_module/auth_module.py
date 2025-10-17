# auth_module.py (corregido)
"""
Módulo de autenticación de usuarios seguro con FastAPI y SQLAlchemy.
Incluye registro, login, verificación de token JWT, roles y políticas de contraseña.
"""

import os
import re
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Table
from sqlalchemy.orm import relationship, declarative_base
from pydantic import BaseModel, EmailStr, ValidationError as PydanticValidationError

# --- Configuration ---
JWT_SECRET = os.environ.get('JWT_SECRET', 'testsecret')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
COMMON_PASSWORDS = {"password", "123456", "qwerty", "password123", "password123!"}

# --- Database Setup ---
Base = declarative_base()

# Association table for many-to-many relationship between users and roles
user_roles_table = Table(
    'user_roles', 
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True)
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    roles = relationship("Role", secondary=user_roles_table, back_populates="users")

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    users = relationship("User", secondary=user_roles_table, back_populates="roles")

class UserCreate(BaseModel):
    email: EmailStr

# --- Password Utilities ---
def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def _validate_password(password: str, email: str):
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if ' ' in password:
        raise ValueError("Password cannot contain spaces.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*(),.?:{}|<>]", password):
        raise ValueError("Password must contain at least one special character.")
    email_user = email.split('@')[0].lower()
    if len(email_user) > 2 and email_user in password.lower():
        raise ValueError("Password cannot contain your email address.")
    if password.lower() in COMMON_PASSWORDS:
        raise ValueError("Password is too common.")

# --- User Registration ---
def user_register(db, email: str, password: str, full_name: str) -> User:
    try:
        UserCreate(email=email)
    except PydanticValidationError as e:
        raise e
    if db.query(User).filter(User.email == email).first():
        raise ValueError("Email already registered.")
    _validate_password(password, email)
    hashed_password = get_password_hash(password)
    new_user = User(
        email=email,
        full_name=full_name,
        password_hash=hashed_password,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# --- User Login ---
def user_login(db, email: str, password: str) -> str:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Cambiar mensaje para no revelar si el email existe o no
        raise ValueError("Invalid credentials.")
    if user.locked_until and user.locked_until > datetime.now(timezone.utc).replace(tzinfo=None):
        raise PermissionError("Account is locked.")
    if not check_password(password, user.password_hash):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        db.commit()
        # Cambiar mensaje para no revelar si el email existe o no
        raise ValueError("Invalid credentials.")
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": user.email,
        "exp": datetime.utcnow() + access_token_expires
    }
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

# --- JWT Token Management ---
def verify_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError as e:
        raise jwt.InvalidTokenError(f"Invalid token: {e}")

# --- Role Management ---
def assign_role(db, user_id: int, role_name: str):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError("User not found.")
    if role_name not in ["admin", "user"]:
        raise ValueError(f"Role '{role_name}' is not a valid role.")
    role = db.query(Role).filter(Role.name == role_name).first()
    if not role:
        role = Role(name=role_name)
        db.add(role)
        db.commit()
        db.refresh(role)
    if role not in user.roles:
        user.roles.append(role)
        db.commit()

def get_user_roles(db, user_id: int) -> list[str]:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError("User not found.")
    return [role.name for role in user.roles]

__all__ = [
    'Base',
    'User',
    'Role',
    'get_password_hash',
    'check_password',
    'user_register',
    'user_login',
    'verify_jwt_token',
    'assign_role',
    'get_user_roles',
]
