from fastapi import FastAPI

app = FastAPI()

@app.get("/broken")
def broken(
