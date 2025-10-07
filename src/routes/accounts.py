from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
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
from schemas import UserRegistrationResponseSchema, MessageResponseSchema, UserRegistrationRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201,
    responses={
        409: {
            "model": MessageResponseSchema,
            "description": "User already exists",
        },
        500: {
            "model": MessageResponseSchema,
            "description": "Error occured",
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
                status_code=409,
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
