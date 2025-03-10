from fastapi import Depends, HTTPException, status, APIRouter
from schemas import UserRead, UserCreate, UserUpdate
from database import get_db
from sqlalchemy.orm import Session
from security import decode_token
from fastapi.security import OAuth2PasswordBearer
from database.models.crud import get_user_by_emai

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
router = APIRouter()

async def get_current_user(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
) -> UserRead:
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    email = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    db_user = await get_user_by_email(db, email)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserRead.from_orm(db_user)

async def require_admin(current_user: UserRead = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden: admins only")
    return current_user

@router.post("/api/v1/accounts/refresh/", response_model=UserUpdate)
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}
