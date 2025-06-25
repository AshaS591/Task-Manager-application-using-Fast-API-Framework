from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


SQLALCHEMY_DATABASE_URL = "sqlite:///./taskmanager.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

Base.metadata.create_all(bind=engine)

    

app = FastAPI()

# @app.get('/')
# def task():
#     return 'This Fast API application'

# @app.get('/task/1')
# def task():
#     return {'task_name':1}

# @app.post("/ping")
# def post_test():
#     return {"message": "POST method works"}
