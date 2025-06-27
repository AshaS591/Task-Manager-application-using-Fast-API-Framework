from fastapi import FastAPI,Depends,status,HTTPException,Response
from sqlalchemy import create_engine,Integer,String,Column,Boolean,ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker,Session,relationship
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List

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
    tasks = relationship("Task", back_populates="owner")


class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True,autoincrement=True)
    title = Column(String)
    description = Column(String, default="")
    done = Column(Boolean, default=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="tasks")

#Database tables creation 
Base.metadata.create_all(bind=engine)


class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class CreateTask(BaseModel):
    title : str
    description : str
    done : bool = False

class ShowUser(BaseModel):
    # id : int
    username: str
    tasks : List[CreateTask]
    class Config:
        orm_mode = True

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


pwd_cxt = CryptContext(schemes=["bcrypt"],deprecated = 'auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


SECRET_KEY = "asha@task_manager_application"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def bcrypt(password : str):
    return pwd_cxt.hash(password)
    
def verify_hash(plain_psw,hashed_psw):
    return pwd_cxt.verify(plain_psw,hashed_psw)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now() +  timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_hash(password, user.hashed_password):
        return None
    return user

def verify_token(token : str,credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)  
        return token_data
    except JWTError:
        raise credentials_exception

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token_data = verify_token(token, credentials_exception)
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

app = FastAPI()

@app.post('/register',status_code=status.HTTP_200_OK,response_model = Token)
def register(user : UserCreate, db : Session = Depends(get_db)) :
    db_user = get_user(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_pw = bcrypt(user.password)
    new_user = User(username=user.username, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    token = create_access_token(data={"sub": new_user.username})
    return {"access_token": token, "token_type": "bearer"}

    

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")   
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


    
@app.post('/task')
def create_task(request : CreateTask, db : Session =Depends(get_db),current_user: User = Depends(get_current_user)):
    new_task = Task(**request.dict(), owner_id=current_user.id)
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return new_task

@app.get('/tasks')
def get_all(response : Response,db : Session=Depends(get_db), current_user: User = Depends(get_current_user)):
    tasks = db.query(Task).filter(Task.owner_id == current_user.id).all()
    if not tasks:
        response.status_code=status.HTTP_404_NOT_FOUND

    return tasks

@app.get('/tasks/{id}')
def get_task(id : int,db : Session=Depends(get_db),current_user: User = Depends(get_current_user)):
    task = db.query(Task).filter(Task.id==id,Task.owner_id == current_user.id).first()
    if not task:
        return f'Task with id {id} not found'
    return task

@app.put('/tasks/{id}',status_code=status.HTTP_202_ACCEPTED)
def update(id,request:CreateTask,db:Session=Depends(get_db),current_user: User = Depends(get_current_user)):
    update_id = db.query(Task).filter(Task.id==id,Task.owner_id == current_user.id)
    if not update_id.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f'Task with id {id} you are trying update is not found')
    update_id.update(request.dict())
    db.commit()
    return 'Updated'

@app.delete('/tasks/{id}')
def destroy(id,db:Session=Depends(get_db),current_user: User = Depends(get_current_user)):
    delete_id=db.query(Task).filter(Task.id==id,Task.owner_id == current_user.id)
    if not delete_id.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f'Task with id {id} you are trying delete is not found')

    delete_id.delete(synchronize_session=False)
    db.commit()
    return 'Done'