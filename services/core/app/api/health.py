from fastapi import APIRouter

router = APIRouter()


@router.get("/health", tags=["ops"])
async def health() -> dict:
    return {"status": "ok"}
