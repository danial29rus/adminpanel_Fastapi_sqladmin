from datetime import timedelta, timezone

from fastapi import Depends, Request
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Union
from fastapi import status, HTTPException, Form
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.sql import select
from sqlalchemy.exc import NoResultFound
import os
from models import Users
from database import async_session_maker

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.environ.get("SECRET_AUTH")
ALGORITHM = os.environ.get("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 300


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)

class PasswordRequestForm:
    def __init__(
        self,
        email: str = Form(),
        password: str = Form(),
    ):
        self.email = email
        self.password = password




class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Union[str, None] = None


async def get_user(email: str):
    try:
        async with async_session_maker() as session:
            query = select(Users)\
                .filter_by(email=email)
            result = await session.execute(query)
            user_model = result.scalar_one()
            return user_model
    except NoResultFound:
        return None


async def authenticate_user(email: str, password: str):
    user = await get_user(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt





HTTP_EXCEPTION_REDIRECT_TO_LOGIN = HTTPException(
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    headers={'Location': '/pages/login'}
)

def custom_oauth2_frontend(request: Request):
    token = request.cookies.get("booking_access_token")
    if not token:
        raise HTTP_EXCEPTION_REDIRECT_TO_LOGIN

    return token


async def get_current_user_frontend(request: Request, token: str = Depends(custom_oauth2_frontend)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        expire: str = payload.get("exp")
        if int(expire) - datetime.now(timezone.utc).timestamp() < 0:
            raise HTTP_EXCEPTION_REDIRECT_TO_LOGIN
        email: str = payload.get("sub")
        if email is None:
            raise HTTP_EXCEPTION_REDIRECT_TO_LOGIN
        token_data = TokenData(email=email)
    except JWTError:
        raise HTTP_EXCEPTION_REDIRECT_TO_LOGIN
    user = await get_user(token_data.email)
    if user is None:
        raise HTTP_EXCEPTION_REDIRECT_TO_LOGIN
    return user