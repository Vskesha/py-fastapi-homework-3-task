from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

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
from schemas import UserRegistrationResponseSchema, DetailResponseSchema, UserRegistrationRequestSchema, \
    MessageResponseSchema, UserActivationRequestSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "model": DetailResponseSchema,
            "description": "User already exists",
        },
        500: {
            "model": DetailResponseSchema,
            "description": "Error occurred",
        },
    }
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        existing_user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        user_group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))

        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )

        db.add(user)
        await db.flush()

        token = ActivationTokenModel(user_id=user.id)
        db.add(token)
        await db.commit()

        return user

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    responses={
        400: {
            "model": DetailResponseSchema,
            "description": "Invalid or expired activation token.",
        },
    }
)
async def activate_user(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == data.email)
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    if (
            not user.activation_token
            or user.activation_token.token != data.token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, user.activation_token.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.execute(
            delete(ActivationTokenModel)
            .where(ActivationTokenModel.id == user.activation_token.id)
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.execute(
            delete(ActivationTokenModel)
            .where(ActivationTokenModel.id == user.activation_token.id)
        )
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
async def request_password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(
        select(UserModel)
        .where(UserModel.email == data.email)
    )

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )

        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    responses={
        400: {
            "model": DetailResponseSchema,
            "description": "Invalid email or token.",
        },
        500: {
            "model": DetailResponseSchema,
            "description": "An error occurred while resetting the password.",
        },
    }
)
async def complete_password_reset(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        user = await db.scalar(
            select(UserModel)
            .where(UserModel.email == data.email)
        )

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        reset_token = await db.scalar(
            select(PasswordResetTokenModel)
            .where(
                PasswordResetTokenModel.user_id == user.id,
                PasswordResetTokenModel.token == data.token
            )
        )

        if not reset_token:
            await db.execute(
                delete(PasswordResetTokenModel)
                .where(PasswordResetTokenModel.user_id == user.id)
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        expires_at = cast(datetime, reset_token.expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            await db.execute(
                delete(PasswordResetTokenModel)
                .where(PasswordResetTokenModel.id == reset_token.id)
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = data.password
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.id == reset_token.id)
        )
        await db.commit()

        return MessageResponseSchema(
            message="Password reset successfully."
        )

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        401: {
            "model": DetailResponseSchema,
            "description": "Invalid email or password.",
        },
        403: {
            "model": DetailResponseSchema,
            "description": "User account is not activated.",
        },
        500: {
            "model": DetailResponseSchema,
            "description": "An error occurred while processing the request.",
        },
    }
)
async def login_user(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    try:
        user = await db.scalar(
            select(UserModel)
            .where(UserModel.email == data.email)
        )

        if not user or not user.verify_password(data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
