from fastapi import APIRouter

router = APIRouter(prefix="/orders", tags=["orders"])


@router.get("/{order_id}")
def get_order(order_id: str):
    return {"id": order_id}
