from fastapi import FastAPI


app = FastAPI()

@app.get('/')
def task():
    return 'This Fast API application'