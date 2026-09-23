from fastapi import APIRouter, Depends, FastAPI, File, UploadFile

app = FastAPI()
router = APIRouter(prefix="/users")

def current_user():
    return {"id": "u1"}

def require_admin():
    return True

@app.get("/health")
def health():
    return {"ok": True}

@router.get("/{id}")
def get_user(id: str, expand: str = "no"):
    return {"id": id, "expand": expand}

@router.post("/", dependencies=[Depends(require_admin)])
def create_user(name: str, user=Depends(current_user)):
    return {"name": name}

@router.post("/upload")
def upload(file: UploadFile = File(...), user=Depends(current_user)):
    return {"filename": file.filename}

app.include_router(router, prefix="/api")

# @app.get("/commented-out")
doc = '@router.post("/not-a-route")'
