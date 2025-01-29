import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert

from config import get_settings
from database import (
    reset_database,
    get_db_contextmanager,
    UserGroupEnum,
    UserGroupModel,
)
from database.populate import CSVDatabaseSeeder
from main import app
from security.token_manager import JWTAuthManager


@pytest.fixture(scope="function", autouse=True)
def reset_db():
    reset_database()


@pytest.fixture(scope="function")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="function")
def db_session():
    with get_db_contextmanager() as session:
        yield session


@pytest.fixture(scope="function")
def jwt_manager():
    settings = get_settings()
    return JWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=settings.JWT_SIGNING_ALGORITHM,
    )


@pytest.fixture(scope="function")
def seed_user_groups(db_session):
    groups = [{"name": group.value} for group in UserGroupEnum]
    db_session.execute(insert(UserGroupModel).values(groups))
    db_session.commit()
    yield db_session


@pytest.fixture(scope="function")
def seed_database(db_session):
    settings = get_settings()
    seeder = CSVDatabaseSeeder(
        csv_file_path=settings.PATH_TO_MOVIES_CSV, db_session=db_session
    )
    if not seeder.is_db_populated():
        seeder.seed()
    yield db_session
