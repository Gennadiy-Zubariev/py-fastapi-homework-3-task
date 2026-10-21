from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
import schemas.accounts

router = APIRouter()


async def get_user_by_email(
    db: AsyncSession,
    email: str
):
    db_user = await db.scalar(
        select(UserModel).where(UserModel.email == email)
    )
    return db_user


@router.post(
    "/register/",
    response_model=schemas.accounts.UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
        db: Annotated[AsyncSession, Depends(get_db)],
        request_data: schemas.accounts.UserRegistrationRequestSchema
):
    db_user = await get_user_by_email(db=db, email=request_data.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {request_data.email} already exists.")
    group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    if not group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    try:
        new_user = UserModel.create(
            email=request_data.email,
            raw_password=request_data.password,
            group_id=group.id
        )
        db.add(new_user)
        await db.flush()
        activate_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activate_token)
        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    return new_user


@router.post(
    "/activate/",
    response_model=schemas.accounts.MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def activate_user(
        db: Annotated[AsyncSession, Depends(get_db)],
        request_data: schemas.accounts.UserActivationRequestSchema
):
    db_user = await get_user_by_email(db=db, email=request_data.email)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )
    activation_token = await db.scalar(
        select(ActivationTokenModel).
        where(
            ActivationTokenModel.token == request_data.token,
            ActivationTokenModel.user_id == db_user.id
        )
    )
    if (
        not activation_token
        or activation_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    db_user.is_active = True
    try:
        await db.delete(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user activation."
        )
    return schemas.accounts.MessageResponseSchema(
        message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
    response_model=schemas.accounts.MessageResponseSchema
)
async def request_password_reset_token(
    db: Annotated[AsyncSession, Depends(get_db)],
    request_data: schemas.accounts.PasswordResetRequestSchema
):
    db_user = await get_user_by_email(db=db, email=request_data.email)
    if db_user and db_user.is_active:
        try:
            await db.execute(
                delete(PasswordResetTokenModel)
                .where(PasswordResetTokenModel.user_id == db_user.id)
            )
            db.add(PasswordResetTokenModel(user_id=db_user.id))
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
    return schemas.accounts.MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
    response_model=schemas.accounts.MessageResponseSchema,
)
async def reset_password(
    db: Annotated[AsyncSession, Depends(get_db)],
    request_data: schemas.accounts.PasswordResetCompleteRequestSchema
):
    db_user = await get_user_by_email(db=db, email=request_data.email)
    if not db_user or not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    db_user_reset_password_token = await db.scalar(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id))
    if (
        not db_user_reset_password_token
        or db_user_reset_password_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
        or db_user_reset_password_token.token != request_data.token
    ):
        if db_user_reset_password_token:
            await db.delete(db_user_reset_password_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    try:
        db_user.password = request_data.password
        await db.delete(db_user_reset_password_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
    return schemas.accounts.MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post(
    "/login/",
    status_code=status.HTTP_200_OK,
    response_model=schemas.accounts.UserLoginResponseSchema
)
async def login_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    request_data: schemas.accounts.UserLoginRequestSchema,
    jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
    settings: Annotated[BaseAppSettings, Depends(get_settings)],
):
    db_user = await get_user_by_email(db=db, email=request_data.email)
    if not db_user or not db_user.verify_password(request_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": db_user.id})
    jwt_access_token = jwt_manager.create_access_token({"user_id": db_user.id})
    try:
        refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token,
        )
        db.add(refresh_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )
    return schemas.accounts.UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    status_code=status.HTTP_200_OK,
    response_model=schemas.accounts.TokenRefreshResponseSchema
)
async def refresh_token(
    db: Annotated[AsyncSession, Depends(get_db)],
    request_data: schemas.accounts.TokenRefreshRequestSchema,
    jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
):
    try:
        decoded_refresh = jwt_manager.decode_refresh_token(request_data.refresh_token)
        user_id = decoded_refresh.get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )
    db_refresh_token = await db.scalar(
        select(RefreshTokenModel).
        where(RefreshTokenModel.token == request_data.refresh_token))
    if not db_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
    if (
        db_refresh_token.user_id != user_id
        or db_refresh_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token."
        )
    db_user = await db.scalar(
        select(UserModel).
        where(UserModel.id == user_id)
    )
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    access_token = jwt_manager.create_access_token({"user_id": user_id})
    return schemas.accounts.TokenRefreshResponseSchema(
        access_token=access_token
    )
