"""SQLAlchemy 2.x database connectivity, session factory, and SQLite/PostgreSQL support."""

from typing import Generator
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from app.config import get_settings
from app.logging_config import get_logger

logger = get_logger("footprintiq.database")


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""
    pass


def build_engine(database_url: str):
    """Builds an engine configured specifically for the target database dialect."""
    connect_args = {}
    is_sqlite = database_url.startswith("sqlite")

    if is_sqlite:
        # SQLite needs check_same_thread=False for async FastAPI request thread pools
        connect_args["check_same_thread"] = False

    engine = create_engine(
        database_url,
        connect_args=connect_args,
        pool_pre_ping=True,  # Proactively test dead connections
        echo=False
    )

    if is_sqlite:
        # Enforce foreign key constraints and Write-Ahead Logging (WAL) in SQLite
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    return engine


# Centralized engine and sessionmaker
settings = get_settings()
engine = build_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


from contextlib import contextmanager


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency providing a transactional database session per request."""
    session = SessionLocal()
    try:
        yield session
    except Exception as exc:
        session.rollback()
        logger.error(f"Database session rolled back due to error: {exc}")
        raise
    finally:
        session.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """Context manager providing a transactional database session for background tasks and services."""
    session = SessionLocal()
    try:
        yield session
    except Exception as exc:
        session.rollback()
        logger.error(f"Database session rolled back due to error: {exc}")
        raise
    finally:
        session.close()



def check_database_connection(target = None, engine_override = None) -> tuple[bool, str]:
    """Validates the live database connection by executing a lightweight probe query."""
    target = target or engine_override
    try:
        if target is None:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        elif isinstance(target, Session):
            target.execute(text("SELECT 1"))
        elif hasattr(target, "connect"):
            with target.connect() as conn:
                conn.execute(text("SELECT 1"))
        else:
            target.execute(text("SELECT 1"))
        return True, "Database connection operational."
    except Exception as exc:
        err_msg = f"Database probe failed: {exc.__class__.__name__}"
        logger.warning(err_msg)
        return False, err_msg

