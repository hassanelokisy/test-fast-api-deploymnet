import sqlalchemy.orm as _orm
import email_validator as _check_email
import fastapi as _fastapi
import passlib.hash as _hash
import jwt as _jwt
import fastapi.security as _security

import database as _database
import models as _models
import schemas as _schemas 


_JWT_SECRET = "thisnotsecurepasswordatallmyfriend"
_ALGORITHM = "HS256"

oauth2schema = _security.OAuth2PasswordBearer("/api/token")


def create_database():
    return _database.Base.metadata.create_all(bind=_database.engine)


def get_db():
    db = _database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_user_by_email(db: _orm.Session, email: str) -> _models.User:
    return db.query(_models.User).filter(_models.User.email == email).first()


async def create_user(user: _schemas.UserCreate, db: _orm.Session):
    try:
        valid = _check_email.validate_email(email=user.email)
        email = valid.email
    except _check_email.EmailNotValidError:
        raise _fastapi.HTTPException(
            status_code=_fastapi.status.HTTP_404_NOT_FOUND,
            detail="Please enter a valid email"
        )
    user_obj = _models.User(
        email=email,
        hashed_password=_hash.bcrypt.hash(user.password)
    )
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    return user_obj


async def create_token(user: _models.User):
    user_obj = _schemas.User.from_orm(user)
    user_dict = user_obj.dict()
    del user_dict["date_created"]

    encoded_jwt = _jwt.encode(
        user_dict,
        _JWT_SECRET,
        _ALGORITHM
    )
    token = _schemas.Token(
        access_token=encoded_jwt,
        token_type="bearer"
    )
    return token.dict()


async def authenticate_user(email: str, password: str, db: _orm.Session):
    user = await get_user_by_email(db=db, email=email)
    if not user:
        return False

    if not user.verify_password(password):
        return False
    return user


async def get_current_user(
    db: _orm.Session = _fastapi.Depends(get_db),
    token: str = _fastapi.Depends(oauth2schema)
):
    try:
        print(token)
        payload = _jwt.decode(token, _JWT_SECRET, algorithms=[_ALGORITHM])
        user = db.query(_models.User).get(payload["id"])
    except:
        raise _fastapi.HTTPException(
            status_code=_fastapi.status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Email or Password"
        )
    return _schemas.User.from_orm(user)


async def create_post(user: _schemas.User, post: _schemas.PostCreate, db: _orm.Session):
    post = _models.Post(**post.dict(), owner_id=user.id)
    db.add(post)
    db.commit()
    db.refresh(post)
    return _schemas.Post.from_orm(post)


async def get_user_posts(user: _schemas.User, db: _orm.Session):
    posts = db.query(_models.Post).filter_by(owner_id=user.id)
    return list(map(_schemas.Post.from_orm, posts))
