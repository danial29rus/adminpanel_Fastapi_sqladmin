import os
from datetime import timedelta
from starlette.responses import Response, HTMLResponse, RedirectResponse

from sqladmin import ModelView, Admin
from sqlalchemy import Column, Integer, String, create_engine, ForeignKey
from sqlalchemy.orm import Session, context
from sqlalchemy.ext.declarative import declarative_base
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from fastapi_login import LoginManager
from fastapi import Form

from manager import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token

Base = declarative_base()
engine = create_engine(
    "sqlite:///example.db",
    connect_args={"check_same_thread": False},
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    hashed_password = Column(String)

    def verify_password(self, password: str):
        return pwd_context.verify(password, self.hashed_password)


class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    user_id = Column(Integer,nullable=False)


class UserAdmin(ModelView, model=User):
    column_list = [User.id, User.name]


class ItemAdmin(ModelView, model=Item):
    column_list = [Item.id, Item.name, Item.user_id]


Base.metadata.create_all(engine)  # Create tables

app = FastAPI()
login_manager = LoginManager("secret-key", token_url="/auth/token")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

admin = Admin(app, engine)

admin.add_view(UserAdmin)
admin.add_view(ItemAdmin)


@login_manager.user_loader
def user_loader(username: str):
    with Session(engine) as session:
        user = session.query(User).filter_by(name=username).first()
        return user


@app.get("/")
def registration_page():
    return HTMLResponse(f"""
        <form action="/login" method="post">
            <label>Username: <input type="text" name="username"></label><br>
            <label>Password: <input type="password" name="password"></label><br>
            <button type="submit">Login</button>
        </form>
        <p>Don't have an account? <a href="/register">Register</a></p>
    """)


@app.get("/register")
def registration_page():
    return HTMLResponse("""
        <form action="/create_user" method="post">
            <label>Username: <input type="text" name="username"></label><br>
            <label>Password: <input type="password" name="password"></label><br>
            <button type="submit">Register</button>
        </form>
    """)


@app.post("/create_user")
def create_user(username: str = Form(...), password: str = Form(...)):
    with Session(engine) as session:
        user = session.query(User).filter_by(name=username).first()
        if user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT
            )
        hashed_password = pwd_context.hash(password)
        new_user = User(name=username, hashed_password=hashed_password)
        session.add(new_user)
        session.commit()
        return HTMLResponse(f"""
            <h1>Account created successfully!</ <p>Successfully created user: {username}</p>
    <p>Go back to <a href="/">login page</a></p>
""")


@app.post("/login")
def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), ):
    username = form_data.username
    password = form_data.password
    with Session(engine) as session:
        user = session.query(User).filter_by(name=username).first()
        if not user or not user.verify_password(password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        response.set_cookie("booking_access_token", access_token)
        return RedirectResponse(url="admin")
