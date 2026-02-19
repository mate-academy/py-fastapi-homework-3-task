from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager
from database import get_db
from exceptions import TokenExpiredError, InvalidTokenError

from security.interfaces import JWTAuthManagerInterface
from schemas import accounts as schemas_accounts
from crud import accounts as crud_accounts

router = APIRouter()


@router.post(
    "/register/",
    response_model=schemas_accounts.UserRegistrationResponseSchema,
    status_code=201,
)
async def register_user_endpoint(
    user: schemas_accounts.UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await crud_accounts.get_user_by_email(db=db, email=user.email)

    if not db_user:
        return await crud_accounts.create_user(db=db, user=user)
    raise HTTPException(
        status_code=409,
        detail=f"A user with this email {db_user.email} already exists.",
    )


@router.post("/activate/", response_model=schemas_accounts.MessageResponseSchema)
async def activate_user_endpoint(
    user_data: schemas_accounts.UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await crud_accounts.get_user_by_email(db=db, email=user_data.email)

    if db_user is None:
        raise HTTPException(status_code=400, detail="Email or token is incorrect")

    validate_token = await crud_accounts.validate_activation_token(
        user=db_user, token=user_data.token
    )

    if validate_token:
        user = await crud_accounts.check_and_change_user_status(db=db, user=db_user)
        activation_token = user.activation_token

        await crud_accounts.delete_activation_token(db=db, token=activation_token)
        return {"message": "User account activated successfully."}
    raise HTTPException(status_code=400, detail="Invalid or expired activation token.")


@router.post(
    "/password-reset/request/", response_model=schemas_accounts.MessageResponseSchema
)
async def password_reset_endpoint(
    email: schemas_accounts.PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await crud_accounts.get_user_by_email(db=db, email=email.email)

    if db_user is not None and db_user.is_active:
        if db_user.password_reset_token:
            await crud_accounts.delete_password_reset_token(db=db, user=db_user)
        await crud_accounts.create_password_reset_token(db=db, user=db_user)
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/", response_model=schemas_accounts.MessageResponseSchema
)
async def password_reset_complete_endpoint(
    user_data: schemas_accounts.PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await crud_accounts.get_user_by_email(db=db, email=user_data.email)

    if db_user is None or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    validate_token = await crud_accounts.validate_reset_token(
        user=db_user, token=user_data.token
    )

    if validate_token:
        await crud_accounts.update_user_password(
            db=db, user=db_user, password=user_data.password
        )
        await crud_accounts.delete_password_reset_token(db=db, user=db_user)
        return {"message": "Password reset successfully."}
    await crud_accounts.delete_password_reset_token(db=db, user=db_user)
    raise HTTPException(status_code=400, detail="Invalid email or token.")


@router.post(
    "/login/", response_model=schemas_accounts.UserLoginResponseSchema, status_code=201
)
async def login_endpoint(
    user_data: schemas_accounts.UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):

    db_user = await crud_accounts.get_user_by_email(db=db, email=user_data.email)
    if db_user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    verify_password = db_user.verify_password(raw_password=user_data.password)
    if not verify_password:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    refresh_token = jwt_manager.create_refresh_token(data={"user_id": db_user.id})
    access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})

    await crud_accounts.create_refresh_token(
        db=db, user_id=db_user.id, token=refresh_token, days_valid=1
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/refresh/",
    response_model=schemas_accounts.TokenRefreshResponseSchema,
    status_code=200,
)
async def get_access_token_endpoint(
    user_data: schemas_accounts.TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):

    try:
        decode_token = jwt_manager.decode_refresh_token(token=user_data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")

    check_exist_token_in_db = await crud_accounts.check_exist_refresh_token_in_db(
        db=db, refresh_token=user_data.refresh_token
    )

    if check_exist_token_in_db is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    check_exist_user_in_db = await crud_accounts.get_user_by_id(
        db=db, user_id=int(decode_token["user_id"])
    )

    if check_exist_user_in_db is None:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(
        data={"user_id": check_exist_user_in_db.id}
    )

    return {"access_token": access_token}
