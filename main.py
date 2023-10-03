import os as _os
from typing import List

import fastapi as _fastapi
import jwt as _jwt
import passlib.hash as _hash
import email_validator as _email_check
import fastapi.security as _security
import sqlalchemy.orm as _orm

import services as _services
import schemas as _schemas

app = _fastapi.FastAPI()

_services.create_database()


@app.get("/", summary="i hate u")
def main():
    return {"Message": "I HATE U SALMA TAREK..."}


@app.post("/api/users")
async def create_user(
    user: _schemas.UserCreate,
    db: _orm.Session = _fastapi.Depends(_services.get_db)
):
    db_user = await _services.get_user_by_email(email=user.email, db=db)
    if db_user:
        raise _fastapi.HTTPException(
            status_code=_fastapi.status.HTTP_400_BAD_REQUEST,
            detail="User with that email already exists."
        )
    model_user = await _services.create_user(user=user, db=db)
    return await _services.create_token(user=model_user)


@app.post("/api/token")
async def generate_token(
    form_data: _security.OAuth2PasswordRequestForm = _fastapi.Depends(),
    db: _orm.Session = _fastapi.Depends(_services.get_db)
):
    user = await _services.authenticate_user(
        email=form_data.username,
        password=form_data.password,
        db=db
    )
    if not user:
        raise _fastapi.HTTPException(
            status_code=_fastapi.status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Credentials",
        )
    return await _services.create_token(user=user)


@app.get("/api/users/me", response_model=_schemas.User)
async def get_user(user: _schemas.User = _fastapi.Depends(_services.get_current_user)):
    return user


@app.post("/api/user_posts", response_model=_schemas.Post)
async def create_post(
    post: _schemas.PostCreate,
    db: _orm.Session = _fastapi.Depends(_services.get_db),
    user: _schemas.User = _fastapi.Depends(_services.get_current_user)
):
    return await _services.create_post(user=user, db=db, post=post)


@app.get("/api/my-posts", response_model=List[_schemas.Post])
async def get_user_posts(
    user: _schemas.User = _fastapi.Depends(_services.get_current_user),
    db: _orm.Session = _fastapi.Depends(_services.get_db)
):
    return await _services.get_user_posts(user=user, db=db)
