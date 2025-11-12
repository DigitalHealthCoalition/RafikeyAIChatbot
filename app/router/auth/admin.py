import os
from fastapi import APIRouter, Depends, HTTPException, status
from datetime import timedelta, datetime, timezone
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from typing import Annotated
from sqlmodel import Session, select
from ...models import User as UserModel, AdminRole
from ...core.database import SessionDep
from fastapi import Security
from fastapi.security import OAuth2PasswordBearer
import jwt


# Reuse password hashing logic
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_username(session: Session, username: str):
    statement = select(UserModel).where(UserModel.username == username)
    return session.exec(statement).first()

def get_user_by_email(session: Session, email: str):
    statement = select(UserModel).where(UserModel.email == email)
    return session.exec(statement).first()

def authenticate_admin(session: Session, username: str, password: str):
    user = get_user_by_username(session, username)
    if not user or not user.is_admin:
        return False
    if not verify_password(password, user.password):
        return False
    return user

def create_access_token(data: dict, secret_key: str, algorithm: str, expires_delta: timedelta | None = None):
    import jwt
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt

# Settings
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ADMIN_REGISTRATION_CODE = os.getenv("ADMIN_REGISTRATION_CODE", "admin123")  # Should be set in env

router = APIRouter(
    prefix="/admin",
    tags=["Admin Auth"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/login")

def get_current_admin(session: SessionDep, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = get_user_by_username(session, username)
        if user is None or not user.is_admin:
            raise credentials_exception
        return user
    except Exception:
        raise credentials_exception

def require_role(required_roles: list[AdminRole]):
    def role_checker(
        current_admin: UserModel = Depends(get_current_admin)
    ):
        if current_admin.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {required_roles}, found: {current_admin.role}"
            )
        return current_admin
    return role_checker

# Pydantic models
class AdminRegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    admin_code: str
    role: AdminRole = AdminRole.viewer

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class AdminResponse(BaseModel):
    id: int | None
    username: str
    email: str
    is_admin: bool
    role: AdminRole
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class RegisterResponse(BaseModel):
    message: str
    admin: AdminResponse

# Admin registration endpoint
@router.post("/register", response_model=RegisterResponse)
async def register_admin(
    admin_data: AdminRegisterRequest,
    session: SessionDep
):
    # Check admin code
    if admin_data.admin_code != ADMIN_REGISTRATION_CODE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin registration code"
        )
    # Check if username or email already exists
    if get_user_by_username(session, admin_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    if get_user_by_email(session, admin_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    # Hash password
    hashed_password = get_password_hash(admin_data.password)

    # Only allow super_admin creation if there is already a super_admin in the system
    requested_role = admin_data.role
    if requested_role == AdminRole.super_admin:
        existing_super_admin = session.exec(
            select(UserModel).where(UserModel.role == AdminRole.super_admin)
        ).first()
        if existing_super_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Super admin can only be created by another super admin"
            )

    # Create admin user
    new_admin = UserModel(
        username=admin_data.username,
        email=admin_data.email,
        password=hashed_password,
        is_admin=True,
        role=admin_data.role,
        disabled=False,
        terms_accepted=True,  # Admins must accept terms
        created_at=datetime.utcnow()
    )
    session.add(new_admin)
    session.commit()
    session.refresh(new_admin)
    admin_response = AdminResponse(
        id=new_admin.id,
        username=new_admin.username,
        email=new_admin.email,
        is_admin=new_admin.is_admin,
        role=new_admin.role,
        created_at=new_admin.created_at
    )
    # Send credentials email (send plain password as provided)
    await send_admin_credentials_email(
        email=new_admin.email,
        username=new_admin.username,
        password=admin_data.password,
        role=new_admin.role
    )
    return RegisterResponse(
        message="Admin registered successfully",
        admin=admin_response
    )

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

async def send_admin_credentials_email(email: str, username: str, password: str, role: str):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    try:
        subject = "Your Rafikey Admin Account Credentials"
        html_body = f"""
        <html>
        <body>
            <h2>Welcome to Rafikey Admin Panel</h2>
            <p>Your admin account has been created with the following credentials:</p>
            <ul>
                <li><b>Username:</b> {username}</li>
                <li><b>Password:</b> {password}</li>
                <li><b>Role:</b> {role}</li>
            </ul>
            <p>Please log in and change your password as soon as possible.</p>
            <p>For security, do not share these credentials with anyone.</p>
            <br>
            <p>Best regards,<br>Rafikey Team</p>
        </body>
        </html>
        """
        text_body = f"""Welcome to Rafikey Admin Panel

Your admin account has been created with the following credentials:

Username: {username}
Password: {password}
Role: {role}

Please log in and change your password as soon as possible.
For security, do not share these credentials with anyone.

Best regards,
Rafikey Team
"""
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = EMAIL_ADDRESS
        message["To"] = email

        text_part = MIMEText(text_body, "plain")
        html_part = MIMEText(html_body, "html")
        message.attach(text_part)
        message.attach(html_part)

        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                server.send_message(message)
        else:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                server.send_message(message)
    except Exception as e:
        print(f"Failed to send admin credentials email to {email}: {str(e)}")
        pass

# Admin login endpoint
@router.post("/login", response_model=Token)
async def login_admin(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep
):
    admin = authenticate_admin(session, form_data.username, form_data.password)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect admin username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": admin.username,
            "is_admin": True,
            "role": str(admin.role) if hasattr(admin, "role") else None
        },
        secret_key=SECRET_KEY,
        algorithm=ALGORITHM,
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@router.get("/list", response_model=list[AdminResponse])
async def list_admins(
    session: SessionDep,
    current_admin: UserModel = Depends(require_role([AdminRole.super_admin]))
):
    """
    List all admin users.
    Only accessible by super_admin.
    """
    admins = session.exec(
        select(UserModel).where(UserModel.is_admin == True)
    ).all()
    return [
        AdminResponse(
            id=admin.id,
            username=admin.username,
            email=admin.email,
            is_admin=admin.is_admin,
            role=admin.role,
            created_at=admin.created_at
        )
        for admin in admins
    ]

@router.delete("/delete/{admin_id}", status_code=204)
async def delete_admin(
    admin_id: int,
    session: SessionDep,
    current_admin: UserModel = Depends(require_role([AdminRole.super_admin]))
):
    """
    Delete an admin user by ID. Only accessible by super_admin.
    """
    admin_to_delete = session.get(UserModel, admin_id)
    if not admin_to_delete or not admin_to_delete.is_admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    if admin_to_delete.role == AdminRole.super_admin:
        raise HTTPException(status_code=403, detail="Cannot delete a super admin")
    session.delete(admin_to_delete)
    session.commit()
    return {"detail": "Admin deleted successfully"}
