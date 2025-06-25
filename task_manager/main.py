from fastapi import FastAPI,Depends,status
from sqlalchemy import create_engine,Integer,String,Column
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker,Session
from pydantic import BaseModel


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

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



app = FastAPI()

# @app.get('/')
# def task():
#     return 'This Fast API application'

# @app.get('/task/1')
# def task():
#     return {'task_name':1}

@app.post('/register',status_code=status.HTTP_200_OK,response_model = ShowUser)
def create_user(request : UserCreate, db : Session = Depends(get_db)) :
    new_user = User(id=request.id,username=request.username,hashed_password = request.password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user
    


    
