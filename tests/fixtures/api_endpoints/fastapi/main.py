"""A small FastAPI app fixture for the api_endpoints detector."""
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()


@app.get("/v1/users")
def list_users():
    return []


@app.post("/v1/users")
def create_user():
    return {}


@router.delete("/v1/users/{user_id}")
def delete_user(user_id: str):
    return {}


@router.patch("/v1/users/{user_id}/role")
def set_role(user_id: str):
    return {}
