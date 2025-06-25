from fastapi import FastAPI,Depends,status,HTTPException
from sqlalchemy import create_engine,Integer,String,Column
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker,Session
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta


#database creation
SQLALCHEMY_DATABASE_URL = "sqlite:///./taskmanager.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}) 
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()



class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True,autoincrement=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

#Database tables creation
Base.metadata.create_all(bind=engine)


class UserCreate(BaseModel):
    username: str
    password: str

class ShowUser(BaseModel):
    # id : int
    username: str
    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    username: str
    password: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


pwd_cxt = CryptContext(schemes=["bcrypt"],deprecated = 'auto')

class Hash():

    def bcrypt(password : str):
        return pwd_cxt.hash(password)
    
    def verify(hashed_psw,plain_psw):
        return pwd_cxt.verify(plain_psw,hashed_psw)
    
SECRET_KEY = "asha@task_manager_application"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now() +  timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

app = FastAPI()

# @app.get('/')
# def task():
#     return 'This Fast API application'

# @app.get('/task/1')
# def task():
#     return {'task_name':1}

@app.post('/register',status_code=status.HTTP_200_OK,response_model = ShowUser)
def create_user(request : UserCreate, db : Session = Depends(get_db)) :
    new_user = User(username=request.username,hashed_password = Hash.bcrypt(request.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user
    

@app.post('/login')
def login(request: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid username")
    
    if not Hash.verify(user.hashed_password, request.password):
        raise HTTPException(status_code=400, detail="Incorrect password")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}
    
