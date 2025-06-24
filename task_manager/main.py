from fastapi import FastAPI


app = FastAPI()

@app.get('/')
def task():
    return 'This Fast API application'

@app.get('/task/1')
def task():
    return {'task_name':1}
