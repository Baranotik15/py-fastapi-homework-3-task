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
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.token_manager import JWTAuthManager
from exceptions.security import TokenExpiredError, InvalidTokenError
router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:

    result = await db.execute(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )

    if result.scalar():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    group_result = await db.execute(
        select(
            UserGroupModel
        ).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )

    user_group = group_result.scalar_one()

    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    try:
        new_user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=user_group.id,
        )

        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(
            user=new_user,
        )

        db.add(activation_token)

        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return new_user


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED
)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:

    user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )

    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )
    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id}
    )

    try:
        token_obj = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(token_obj)
        await db.commit()

    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post("/activate/")
async def activate_user(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:

    query = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == user_data.email)
    )

    result = await db.execute(query)

    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="User not found."
        )

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    if not user.activation_token or user.activation_token.token != user_data.token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    expires_at = user.activation_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    
    await db.delete(user.activation_token)
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )
