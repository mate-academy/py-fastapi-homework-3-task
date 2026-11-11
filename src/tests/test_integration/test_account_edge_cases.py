import asyncio
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from database import (
    ActivationTokenModel,
    Base,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from main import app


@pytest.mark.asyncio
async def test_registration_checks_normalized_email(client, seed_user_groups):
    payload = {"email": "Person@Example.com", "password": "StrongPass1!"}

    first = await client.post("/api/v1/accounts/register/", json=payload)
    assert first.status_code == 201
    assert first.json()["email"] == "person@example.com"

    payload["email"] = "person@example.com"
    duplicate = await client.post("/api/v1/accounts/register/", json=payload)
    assert duplicate.status_code == 409


@pytest.mark.asyncio
async def test_active_user_without_activation_token_gets_active_message(client, db_session, seed_user_groups):
    group = await db_session.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user = UserModel.create(email="active@example.com", raw_password="StrongPass1!", group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    response = await client.post(
        "/api/v1/accounts/activate/",
        json={"email": "active@example.com", "token": "already-used"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "User account is already active."


@pytest.mark.asyncio
async def test_fast_logins_create_distinct_refresh_tokens(client, db_session, seed_user_groups):
    group = await db_session.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user = UserModel.create(email="login@example.com", raw_password="StrongPass1!", group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()
    payload = {"email": "login@example.com", "password": "StrongPass1!"}
    fixed_time = datetime.now(timezone.utc)

    with patch("security.token_manager.datetime") as clock:
        clock.now.return_value = fixed_time
        first = await client.post("/api/v1/accounts/login/", json=payload)
        second = await client.post("/api/v1/accounts/login/", json=payload)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["refresh_token"] != second.json()["refresh_token"]
    stored_tokens = (await db_session.scalars(select(RefreshTokenModel))).all()
    assert len(stored_tokens) == 2


@pytest.mark.asyncio
async def test_refresh_rejects_a_token_stored_for_another_user(client, db_session, jwt_manager, seed_user_groups):
    group = await db_session.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    owner = UserModel.create(email="owner@example.com", raw_password="StrongPass1!", group_id=group.id)
    other = UserModel.create(email="other@example.com", raw_password="StrongPass1!", group_id=group.id)
    owner.is_active = True
    other.is_active = True
    db_session.add_all([owner, other])
    await db_session.flush()
    token = jwt_manager.create_refresh_token({"user_id": other.id})
    db_session.add(RefreshTokenModel.create(user_id=owner.id, days_valid=7, token=token))
    await db_session.commit()

    response = await client.post("/api/v1/accounts/refresh/", json={"refresh_token": token})

    assert response.status_code == 401
    assert "access_token" not in response.json()


@pytest.mark.asyncio
async def test_reset_rejects_weak_new_password(client, db_session, seed_user_groups):
    group = await db_session.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user = UserModel.create(email="reset@example.com", raw_password="StrongPass1!", group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.flush()
    token = PasswordResetTokenModel(user_id=user.id)
    db_session.add(token)
    await db_session.commit()

    response = await client.post(
        "/api/v1/accounts/reset-password/complete/",
        json={"email": "reset@example.com", "token": token.token, "password": "weak"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid email or token."


@pytest.mark.asyncio
async def test_refresh_rejects_invalid_token(client):
    response = await client.post("/api/v1/accounts/refresh/", json={"refresh_token": "invalid"})

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid token."


@pytest.mark.asyncio
async def test_registration_rolls_back_unexpected_errors(db_session, seed_user_groups):
    payload = {"email": "failure@example.com", "password": "StrongPass1!"}
    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        with patch("routes.accounts.AsyncSession.commit", side_effect=RuntimeError("unexpected failure")):
            response = await client.post("/api/v1/accounts/register/", json=payload)

    assert response.status_code == 500
    assert response.json()["detail"] == "An error occurred during user creation."
    await db_session.rollback()
    assert await db_session.scalar(select(UserModel.id).where(UserModel.email == payload["email"])) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("password", ["StrongPass1!" + "a" * 61, "StrongPass1!" + "é" * 31, "StrongPass1!\x00"])
async def test_registration_rejects_passwords_bcrypt_cannot_represent(seed_user_groups, password):
    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/accounts/register/", json={"email": "password@example.com", "password": password}
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_registration_accepts_the_bcrypt_byte_limit(client, seed_user_groups):
    too_long = "StrongPass1!" + "a" * 61
    at_limit = "StrongPass1!" + "a" * 60
    payload = {"email": "limit@example.com", "password": too_long}

    assert (await client.post("/api/v1/accounts/register/", json=payload)).status_code == 422
    payload["password"] = at_limit
    assert (await client.post("/api/v1/accounts/register/", json=payload)).status_code == 201


@pytest.mark.asyncio
@pytest.mark.parametrize("password", ["StrongPass1!" + "a" * 61, "StrongPass1!\x00"])
async def test_reset_rejects_passwords_bcrypt_cannot_represent(db_session, seed_user_groups, password):
    group = await db_session.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user = UserModel.create(email="reset-limit@example.com", raw_password="StrongPass1!", group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.flush()
    token = PasswordResetTokenModel(user_id=user.id)
    db_session.add(token)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/accounts/reset-password/complete/",
            json={"email": user.email, "token": token.token, "password": password},
        )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_login_rejects_a_password_with_a_null_character(db_session, seed_user_groups):
    group = await db_session.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user = UserModel.create(email="null-login@example.com", raw_password="StrongPass1!", group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/accounts/login/", json={"email": user.email, "password": "StrongPass1!\x00"}
        )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rejects_deactivated_user(client, db_session, jwt_manager, seed_user_groups):
    group = await db_session.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user = UserModel.create(email="inactive@example.com", raw_password="StrongPass1!", group_id=group.id)
    user.is_active = False
    db_session.add(user)
    await db_session.flush()
    token = jwt_manager.create_refresh_token({"user_id": user.id})
    db_session.add(RefreshTokenModel.create(user_id=user.id, days_valid=7, token=token))
    await db_session.commit()

    response = await client.post("/api/v1/accounts/refresh/", json={"refresh_token": token})

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_refresh_rejects_a_token_with_an_invalid_unicode_character():
    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/accounts/refresh/",
            content=b'{"refresh_token": "\\ud800"}',
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_activation_rejects_a_token_with_an_invalid_unicode_character(db_session, seed_user_groups):
    group = await db_session.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user = UserModel.create(email="unicode@example.com", raw_password="StrongPass1!", group_id=group.id)
    db_session.add(user)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/accounts/activate/",
            content=b'{"email": "unicode@example.com", "token": "\\ud800"}',
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("reset_password", [False, True])
async def test_token_can_only_be_used_once_concurrently(tmp_path, reset_password):
    both_read_token = asyncio.Event()
    token_reads = 0
    token_table = "password_reset_tokens" if reset_password else "activation_tokens"

    class RacingSession(AsyncSession):
        async def scalar(self, statement, *args, **kwargs):
            nonlocal token_reads
            result = await super().scalar(statement, *args, **kwargs)
            if result is not None and f"FROM {token_table}" in str(statement):
                token_reads += 1
                if token_reads == 2:
                    both_read_token.set()
                await asyncio.wait_for(both_read_token.wait(), timeout=10)
            return result

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'accounts.db'}")
    sessions = async_sessionmaker(engine, class_=RacingSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    try:
        async with sessions() as session:
            group = UserGroupModel(name=UserGroupEnum.USER)
            session.add(group)
            await session.flush()
            user = UserModel.create(email="race@example.com", raw_password="StrongPass1!", group_id=group.id)
            user.is_active = reset_password
            session.add(user)
            await session.flush()
            token_model = PasswordResetTokenModel if reset_password else ActivationTokenModel
            token = token_model(user_id=user.id)
            session.add(token)
            await session.commit()
            token_value = token.token

        async def override_db():
            async with sessions() as session:
                yield session

        app.dependency_overrides[get_db] = override_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            route = "reset-password/complete/" if reset_password else "activate/"
            payload = {"email": "race@example.com", "token": token_value}
            if reset_password:
                payloads = [
                    {**payload, "password": "FirstReset1!"},
                    {**payload, "password": "SecondReset1!"},
                ]
            else:
                payloads = [payload, payload]

            responses = await asyncio.gather(
                *(client.post(f"/api/v1/accounts/{route}", json=data) for data in payloads)
            )

        assert sorted(response.status_code for response in responses) == [200, 400]
    finally:
        app.dependency_overrides.pop(get_db, None)
        await engine.dispose()
