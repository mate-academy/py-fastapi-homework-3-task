from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas import (
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema
)

from schemas.accounts import UserRegistrationRequestSchema, UserLoginRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


async def get_user_by_email(email_str: EmailStr, db: AsyncSession):
    stmt = select(UserModel).filter_by(email=email_str)
    result_stmt = await db.execute(stmt)
    db_user = result_stmt.scalar_one_or_none()
    return db_user


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def create_account(account_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        db_user = UserModel.create(
            email=account_data.email,
            raw_password=account_data.password,
            group_id=1,
        )
        db.add(db_user)
        act_token = ActivationTokenModel(
            user=db_user
        )
        db.add(act_token)
        await db.commit()

    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err))
    except IntegrityError:
        raise HTTPException(status_code=409, detail=f"A user with this email {db_user.email} already exists.")
    except Exception:
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )

    return db_user


@router.post("/activate/", response_model=MessageResponseSchema, status_code=200)
async def activate_account(account_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email_str=account_data.email, db=db)
    if db_user:
        if db_user.is_active:
            raise HTTPException(status_code=400, detail="User account is already active.")
        else:
            activation_token = db_user.activation_token
            if activation_token:
                if (
                        activation_token.token == account_data.token
                        and activation_token.expires_at.replace(tzinfo=None)
                        >= datetime.now(timezone.utc).replace(tzinfo=None)
                ):
                    try:
                        db_user.is_active = True
                        await db.delete(activation_token)
                        await db.commit()
                        return {"message": "User account activated successfully."}
                    except Exception as err:
                        await db.rollback()
                        raise HTTPException(status_code=500, detail=str(err))
            raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    raise HTTPException(status_code=404, detail=f"User with email: {account_data.email} not found")


@router.post("/password-reset/request/")
async def password_reset_request(
        account_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(email_str=account_data.email, db=db)
    if db_user:
        if db_user.is_active:
            try:
                if db_user.password_reset_token:
                    await db.delete(db_user.password_reset_token)
                    await db.flush()
                res_token = PasswordResetTokenModel(user=db_user)
                db.add(res_token)
                await db.commit()
            except Exception as exc:
                await db.rollback()
                raise HTTPException(status_code=500, detail=str(exc))
    return JSONResponse(
        status_code=200,
        content={"message": "If you are registered, you will receive an email with instructions."}
    )


@router.post("/reset-password/complete/")
async def password_reset_complete(
        account_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(email_str=account_data.email, db=db)
    invalid_data_err = HTTPException(status_code=400, detail="Invalid email or token.")

    if db_user:
        password_res_token = db_user.password_reset_token
        if password_res_token and db_user.is_active:
            try:
                try:
                    if (
                            password_res_token.token == account_data.token
                            and password_res_token.expires_at.replace(tzinfo=None)
                            >= datetime.now(timezone.utc).replace(tzinfo=None)
                    ):
                        db_user.password = account_data.password
                        return JSONResponse(
                            status_code=200,
                            content={"message": "Password reset successfully."}
                        )
                except Exception:
                    await db.rollback()
                    raise Exception
                finally:
                    await db.delete(password_res_token)
                    await db.commit()
            except Exception:
                raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    raise invalid_data_err


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login_account(
        account_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    db_user = await get_user_by_email(account_data.email, db=db)
    if db_user:
        if not db_user.is_active:
            raise HTTPException(status_code=403, detail="User account is not activated.")

        if db_user.verify_password(account_data.password):
            try:
                access_token = jwt_manager.create_access_token(
                    data={
                        "user_id": db_user.id,
                        "token_type": "access"
                    }
                )
                refresh_token = jwt_manager.create_refresh_token(
                    data={
                        "user_id": db_user.id,
                        "token_type": "refresh"
                    }
                )

                db_refresh_token = RefreshTokenModel.create(
                    user_id=db_user.id,
                    days_valid=settings.LOGIN_TIME_DAYS,
                    token=refresh_token
                )
                db.add(db_refresh_token)
                await db.commit()
            except Exception:
                await db.rollback()
                raise HTTPException(
                    status_code=500,
                    detail="An error occurred while processing the request."
                )

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer"
            }

    raise HTTPException(status_code=401, detail="Invalid email or password.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_request(
        account_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):

    try:
        refresh_token = jwt_manager.decode_refresh_token(account_data.refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")

    refresh_token_stmt = select(RefreshTokenModel).filter_by(token=account_data.refresh_token)
    result_refresh_token_stmt = await db.execute(refresh_token_stmt)
    db_refresh_token = result_refresh_token_stmt.scalar_one_or_none()

    if not db_refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_stmt = select(UserModel).filter_by(id=refresh_token["user_id"])
    result_user_stmt = await db.execute(user_stmt)
    db_user = result_user_stmt.scalar_one_or_none()
    if db_user:
        new_access_token = jwt_manager.create_access_token(
            data={
                "user_id": db_user.id,
                "token_type": "access"
            }
        )
        return {"access_token": new_access_token}
    raise HTTPException(status_code=404, detail="User not found.")
