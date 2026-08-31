"""Pytest configuration and fixtures."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base
from app.database import get_db


@pytest.fixture
def test_db():
    """Create a test database."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    db = TestingSessionLocal()
    yield db
    db.close()


@pytest.fixture
def mock_headers():
    """Mock HTTP headers."""
    return {
        "content-type": "text/html; charset=utf-8",
        "content-length": "1234",
        "server": "nginx/1.21.0",
        "date": "Mon, 01 Jan 2024 00:00:00 GMT",
    }


@pytest.fixture
def mock_headers_secure():
    """Mock secure HTTP headers."""
    return {
        "content-type": "text/html; charset=utf-8",
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "set-cookie": "sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/",
    }
