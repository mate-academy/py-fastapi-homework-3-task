from functools import wraps
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status


def transaction_atomic(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        db: AsyncSession = kwargs.get("db")
        try:
            if not db:
                result = await func(*args, **kwargs)
                return result
            else:
                async with db.begin():
                    result = await func(*args, **kwargs)
                    return result
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error occurred")
    return wrapper
