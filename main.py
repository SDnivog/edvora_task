from enum import unique
import jwt

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model

app = FastAPI(
    title="Edvora",
    description="Edvora task",
    version="0.0.1",
    terms_of_service="https://www.edvora.com/",
    contact={
        "name": "Edvora Amazing",
        "url": "https://www.edvora.com/",
        "email": "careers@edvora.com",
    },
    license_info={
        "name": "Edvora Copyright",
        "url": "https://www.edvora.com/",
    },
)

tags_metadata = [
    {
        "name": "Users",
        "description": "Operations with users. The **login** logic is also here.",
    },
    {
        "name": "Students",
        "description": "Manage items. So _fancy_ they have their own docs.",
        "externalDocs": {
            "description": "Items external docs",
            "url": "https://fastapi.tiangolo.com/",
        },
    },
]

JWT_SECRET = "myjwtsecret"


class AddStudent(Model):
    id = fields.IntField(pk=True)
    student_name = fields.CharField(50, unique=True)
    college = fields.CharField(128)


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


User_Pydantic = pydantic_model_creator(User, name="User")
UserIn_Pydantic = pydantic_model_creator(User, name="UserIn", exclude_readonly=True)

Student_Pydantic = pydantic_model_creator(AddStudent, name="Student")
StudentIn_Pydantic = pydantic_model_creator(
    AddStudent, name="StudentIn", exclude_readonly=True
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user


@app.post("/token", tags=["AccessToken"])
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    user_obj = await User_Pydantic.from_tortoise_orm(user)

    token = jwt.encode(user_obj.dict(), JWT_SECRET)
    refresh_token = jwt.encode(user_obj.dict(), JWT_SECRET)

    return {"access_token": token, "refresh_token": refresh_token}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = await User.get(id=payload.get("id"))
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    return await User_Pydantic.from_tortoise_orm(user)


@app.post("/users", response_model=User_Pydantic, tags=["Users"])
async def create_user(user: UserIn_Pydantic):
    user_obj = User(
        username=user.username, password_hash=bcrypt.hash(user.password_hash)
    )
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)


@app.post("/students", response_model=Student_Pydantic, tags=["Students"])
async def add_student(addstudent: StudentIn_Pydantic):
    student_obj = AddStudent(
        student_name=addstudent.student_name, college=(addstudent.college)
    )
    await student_obj.save()
    return await Student_Pydantic.from_tortoise_orm(student_obj)


@app.get("/users/user_details", response_model=User_Pydantic, tags=["Users"])
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user


register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={"models": ["main"]},
    generate_schemas=True,
    add_exception_handlers=True,
)
