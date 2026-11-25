"""
FootprintIQ - Microsoft SQL Server 2022 Express Database Session Management
Strict Architecture Requirement: Microsoft SQL Server 2022 Express ONLY.
No SQLite. No PostgreSQL. No secondary database.

Provides complete ACID transaction management:
- Atomic context managers (transactional_session)
- Isolation management (READ_COMMITTED_SNAPSHOT)
- Transient failure and deadlock retry handling (SQL Server Error 1205)
- Session lifecycle guarantees preventing connection leaks
"""

import os
import time
import random
import logging
import functools
from typing import Generator, Optional, Callable, Any
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import DBAPIError, OperationalError

logger = logging.getLogger("FootprintIQ.DB")

# Base class for SQLAlchemy ORM models
Base = declarative_base()


def get_database_url() -> str:
    """
    Constructs or retrieves the SQL Server 2022 connection string.
    Supported dialects:
    - mssql+pymssql (pure Python FreeTDS, cross-platform)
    - mssql+pyodbc (ODBC Driver 17/18 for SQL Server)
    """
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url

    host = os.getenv("SQL_SERVER_HOST", "127.0.0.1")
    port = os.getenv("SQL_SERVER_PORT", "1433")
    user = os.getenv("SQL_SERVER_USER", "sa")
    password = os.getenv("SQL_SERVER_PASSWORD", "FootprintIQ2026!")
    database = os.getenv("SQL_SERVER_DATABASE", "FootprintIQ")
    driver = os.getenv("SQL_SERVER_DRIVER", "pymssql")

    if driver == "pyodbc":
        odbc_driver = os.getenv("ODBC_DRIVER", "ODBC Driver 18 for SQL Server")
        return f"mssql+pyodbc://{user}:{password}@{host}:{port}/{database}?driver={odbc_driver}&TrustServerCertificate=yes"
    else:
        return f"mssql+pymssql://{user}:{password}@{host}:{port}/{database}?charset=utf8"


DATABASE_URL = get_database_url()

engine = None
SessionLocal = None


def init_engine(db_url: str = None):
    """
    Initializes the SQLAlchemy engine and thread-safe sessionmaker factory.
    Enforces QueuePool with pre-ping validation and recycle timeouts.
    """
    global engine, SessionLocal
    url = db_url or get_database_url()
    try:
        engine = create_engine(
            url,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_timeout=30,
            pool_recycle=1800,
            pool_pre_ping=True,
            echo=False
        )
        SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
            bind=engine
        )
        logger.info(f"Initialized SQLAlchemy Engine for SQL Server: {url.split('@')[-1] if '@' in url else url}")
        return engine
    except Exception as e:
        logger.warning(f"Could not connect to SQL Server at {url}: {e}")
        return None


# Initialize on import
try:
    init_engine(DATABASE_URL)
except Exception:
    pass


def is_deadlock_error(exc: Exception) -> bool:
    """
    Determines if an exception is an SQL Server deadlock victim (Error 1205)
    or transient connection abort that is safe to retry.
    """
    err_str = str(exc).lower()
    return "1205" in err_str or "deadlock" in err_str or "deadlocked" in err_str


def retry_on_deadlock(max_retries: int = 3, base_delay: float = 0.05, backoff_factor: float = 2.0):
    """
    Decorator for idempotent operations that automatically retries when an
    SQL Server deadlock (Error 1205) is encountered.
    Uses exponential backoff with random jitter to minimize collision recurrence.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            delay = base_delay
            for attempt in range(1, max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if is_deadlock_error(e) and attempt < max_retries:
                        jitter = random.uniform(0.01, 0.05)
                        sleep_time = delay + jitter
                        logger.warning(
                            f"[Deadlock Detected] Retrying operation '{func.__name__}' "
                            f"(attempt {attempt}/{max_retries}) after {sleep_time:.3f}s: {e}"
                        )
                        time.sleep(sleep_time)
                        delay *= backoff_factor
                        last_exc = e
                    else:
                        raise
            if last_exc:
                raise last_exc
        return wrapper
    return decorator


@contextmanager
def transactional_session(session: Optional[Session] = None) -> Generator[Session, None, None]:
    """
    Context manager providing an atomic transaction boundary.
    
    Behavior:
    1. If caller provides an existing active `session`:
       - Joins the caller's transaction via session.begin_nested() (SAVEPOINT in SQL Server).
       - Caller retains ownership; this context does NOT close the caller's session.
    2. If no `session` is provided:
       - Creates a fresh Session from SessionLocal.
       - Begins an outer transaction.
       - Commits automatically if the block exits without exception.
       - Rolls back automatically on any exception.
       - ALWAYS closes the session in a finally block, guaranteeing zero connection leaks.
    """
    if session is not None:
        # Join caller's transaction with savepoint isolation
        nested = session.begin_nested()
        try:
            yield session
            nested.commit()
        except Exception:
            nested.rollback()
            raise
    else:
        if SessionLocal is None:
            init_engine(DATABASE_URL)
        if SessionLocal is None:
            raise ConnectionError("SQL Server 2022 database engine is not initialized.")
        
        db = SessionLocal()
        try:
            with db.begin():
                yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


def get_db() -> Generator[Optional[Session], None, None]:
    """
    FastAPI dependency that provides a transactional database session per HTTP request.
    Validates connection readiness via pre-ping before yielding.
    Guarantees clean commit on HTTP 2xx and rollback on error, followed by session close.
    Yields None if the SQL Server engine is pending connection, allowing repository fallback.
    """
    if SessionLocal is None:
        try:
            init_engine(DATABASE_URL)
        except Exception:
            pass

    if SessionLocal is None:
        yield None
        return

    db = None
    try:
        db = SessionLocal()
        # Pre-ping SQL Server to ensure TDS connection is active
        db.execute(text("SELECT 1"))
    except Exception:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
        yield None
        return

    try:
        yield db
        if db.is_active:
            db.commit()
    except Exception:
        if db is not None and db.is_active:
            db.rollback()
        raise
    finally:
        if db is not None:
            db.close()


def check_rcsi_status() -> dict:
    """
    Checks if READ_COMMITTED_SNAPSHOT is enabled on the current SQL Server database.
    """
    if engine is None:
        return {"status": "UNKNOWN", "is_read_committed_snapshot_on": False}
    try:
        with engine.connect() as conn:
            stmt = text("""
                SELECT is_read_committed_snapshot_on, snapshot_isolation_state_desc
                FROM sys.databases
                WHERE name = DB_NAME()
            """)
            row = conn.execute(stmt).fetchone()
            if row:
                return {
                    "status": "ONLINE",
                    "is_read_committed_snapshot_on": bool(row[0]),
                    "snapshot_isolation_state_desc": row[1]
                }
    except Exception as e:
        return {"status": "ERROR", "error": str(e), "is_read_committed_snapshot_on": False}
    return {"status": "UNKNOWN", "is_read_committed_snapshot_on": False}


def check_db_health() -> dict:
    """
    Checks the connectivity and status of Microsoft SQL Server 2022 Express.
    """
    if engine is None:
        try:
            init_engine(DATABASE_URL)
        except Exception as e:
            return {
                "status": "UNREACHABLE",
                "database": "Microsoft SQL Server 2022 Express",
                "url": DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL,
                "error": str(e)
            }

    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT @@VERSION AS [version], DB_NAME() AS [database]"))
            row = result.fetchone()
            rcsi = check_rcsi_status()
            return {
                "status": "ONLINE",
                "database_product": "Microsoft SQL Server",
                "version": row[0] if row else "Unknown",
                "database_name": row[1] if row else "FootprintIQ",
                "dialect": engine.dialect.name,
                "read_committed_snapshot": rcsi.get("is_read_committed_snapshot_on", False)
            }
    except Exception as e:
        return {
            "status": "OFFLINE",
            "database_product": "Microsoft SQL Server 2022 Express",
            "error": str(e),
            "target": DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL
        }
