import os
import sys
import tempfile
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add the parent directory to the path to find the auth_module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from auth_module import user_login, user_register, verify_jwt_token, User, Base, get_password_hash, check_password, assign_role, get_user_roles
from pydantic import ValidationError
import jwt
import bcrypt

# --- Fixtures ---
@pytest.fixture(scope="module")
def test_db():
    db_fd, db_path = tempfile.mkstemp()
    engine = create_engine(f'sqlite:///{db_path}')
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture(scope="function")
def cleanup_users(test_db):
    test_db.query(User).delete()
    test_db.commit()

# --- Test Data ---
VALID_EMAIL = "test.user@example.com"
VALID_PASSWORD = "StrongP@ssw0rd!"
INVALID_EMAIL = "test.userexample.com"
COMMON_PASSWORD = "password123!"
SHORT_PASSWORD = "Ab1!"
NO_UPPER_PASSWORD = "weakp@ss1!"
NO_LOWER_PASSWORD = "WEAKP@SS1!"
NO_NUMBER_PASSWORD = "WeakPass!"
NO_SPECIAL_PASSWORD = "WeakPass1"
PASSWORD_WITH_SPACE = "Weak Pass1!"
PASSWORD_WITH_EMAIL = "Example1!"

# --- Registration Tests ---
def test_register_valid_user(test_db, cleanup_users):
    user = user_register(
        db=test_db,
        email=VALID_EMAIL,
        password=VALID_PASSWORD,
        full_name="Test User"
    )
    assert user.email == VALID_EMAIL
    assert user.full_name == "Test User"
    assert user.is_active
    assert hasattr(user, 'id')
    assert user.password_hash != VALID_PASSWORD
    assert bcrypt.checkpw(VALID_PASSWORD.encode(), user.password_hash.encode())

def test_register_duplicate_email(test_db, cleanup_users):
    user_register(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")
    with pytest.raises(ValueError):
        user_register(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")

def test_register_invalid_email_format(test_db, cleanup_users):
    with pytest.raises(ValidationError):
        user_register(db=test_db, email=INVALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")

def test_register_short_password(test_db, cleanup_users):
    with pytest.raises(ValueError):
        user_register(db=test_db, email="shortpw@example.com", password=SHORT_PASSWORD, full_name="Short PW")

def test_register_password_no_uppercase(test_db, cleanup_users):
    with pytest.raises(ValueError):
        user_register(db=test_db, email="noupper@example.com", password=NO_UPPER_PASSWORD, full_name="No Upper")

def test_register_password_no_lowercase(test_db, cleanup_users):
    with pytest.raises(ValueError):
        user_register(db=test_db, email="nolower@example.com", password=NO_LOWER_PASSWORD, full_name="No Lower")

def test_register_password_no_number(test_db, cleanup_users):
    with pytest.raises(ValueError):
        user_register(db=test_db, email="nonumber@example.com", password=NO_NUMBER_PASSWORD, full_name="No Number")

def test_register_password_no_special(test_db, cleanup_users):
    with pytest.raises(ValueError):
        user_register(db=test_db, email="nospecial@example.com", password=NO_SPECIAL_PASSWORD, full_name="No Special")

def test_register_password_with_space(test_db, cleanup_users):
    with pytest.raises(ValueError):
        user_register(db=test_db, email="spacepw@example.com", password=PASSWORD_WITH_SPACE, full_name="Space PW")

def test_register_password_contains_email(test_db, cleanup_users):
    with pytest.raises(ValueError):
        user_register(db=test_db, email="example@example.com", password=PASSWORD_WITH_EMAIL, full_name="Example")

def test_register_common_password(test_db, cleanup_users):
    with pytest.raises(ValueError):
        user_register(db=test_db, email="commonpw@example.com", password=COMMON_PASSWORD, full_name="Common PW")

# --- Login Tests ---
def test_login_success(test_db, cleanup_users):
    user_register(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")
    token = user_login(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD)
    assert isinstance(token, str)
    decoded = jwt.decode(token, os.environ.get('JWT_SECRET', 'testsecret'), algorithms=["HS256"])
    assert decoded['sub'] == VALID_EMAIL

def test_login_wrong_password(test_db, cleanup_users):
    user_register(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")
    with pytest.raises(ValueError):
        user_login(db=test_db, email=VALID_EMAIL, password="WrongP@ssw0rd!")

def test_login_wrong_email(test_db, cleanup_users):
    with pytest.raises(ValueError):
        user_login(db=test_db, email="notfound@example.com", password=VALID_PASSWORD)

def test_login_account_lockout(test_db, cleanup_users):
    user_register(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")
    for _ in range(5):
        try:
            user_login(db=test_db, email=VALID_EMAIL, password="WrongP@ssw0rd!")
        except ValueError:
            pass
    with pytest.raises(PermissionError):
        user_login(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD)

# --- JWT Token Verification ---
def test_jwt_token_verification(test_db, cleanup_users):
    user_register(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")
    token = user_login(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD)
    payload = verify_jwt_token(token)
    assert payload['sub'] == VALID_EMAIL

def test_jwt_token_invalid():
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt_token("invalid.token.here")

# --- Role and Permission Tests ---
def test_assign_and_get_role(test_db, cleanup_users):
    user = user_register(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")
    assign_role(db=test_db, user_id=user.id, role_name="admin")
    roles = get_user_roles(db=test_db, user_id=user.id)
    assert "admin" in roles

def test_assign_invalid_role(test_db, cleanup_users):
    user = user_register(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")
    with pytest.raises(ValueError):
        assign_role(db=test_db, user_id=user.id, role_name="invalid_role")

# --- Password Hashing ---
def test_password_hash_and_check():
    password = VALID_PASSWORD
    hash_ = get_password_hash(password)
    assert hash_ != password
    assert check_password(password, hash_)
    assert not check_password("WrongP@ssw0rd!", hash_)

# --- Security: No sensitive info in errors ---
def test_error_message_no_sensitive_info(test_db, cleanup_users):
    try:
        user_login(db=test_db, email="notfound@example.com", password=VALID_PASSWORD)
    except Exception as e:
        msg = str(e)
        assert VALID_PASSWORD not in msg
        assert "password" not in msg.lower()
        assert "hash" not in msg.lower()

# --- SQL Injection Protection ---
def test_sql_injection_protection(test_db, cleanup_users):
    user_register(db=test_db, email=VALID_EMAIL, password=VALID_PASSWORD, full_name="Test User")
    with pytest.raises(ValueError):
        user_login(db=test_db, email="' OR 1=1 --", password=VALID_PASSWORD)
