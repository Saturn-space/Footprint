"""Centralized typed configuration management using Pydantic Settings."""

import os
from functools import lru_cache
from typing import List, Literal, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration with strict validation and environment mapping."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False
    )

    APP_NAME: str = "FootprintIQ - Digital Footprint Investigator"
    APP_VERSION: str = "2.0.0-foundation"
    APP_ENV: Literal["development", "staging", "production", "test"] = "development"
    DEBUG: bool = False

    HOST: str = "127.0.0.1"
    PORT: int = 8000

    DATABASE_URL: str = Field(
        default="sqlite:///./footprintiq.db",
        description="SQLAlchemy database connection URI"
    )

    SECRET_KEY: str = Field(
        default="dev-insecure-secret-key-change-in-production-only",
        description="Cryptographic signing key"
    )

    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_FORMAT: Literal["structured", "standard"] = "structured"

    ALLOWED_HOSTS: List[str] = ["127.0.0.1", "localhost"]

    # Authentication & Session Security Configuration
    SESSION_COOKIE_NAME: str = "footprintiq_session"
    SESSION_MAX_AGE_SECONDS: int = 14400  # 4 hours
    SESSION_COOKIE_SECURE: Optional[bool] = None  # Auto-configured based on APP_ENV if None
    SESSION_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    CSRF_COOKIE_NAME: str = "footprintiq_csrf"
    
    # Account Lockout & Throttling
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # Self-Service User Registration Policy
    ALLOW_PUBLIC_SIGNUP: bool = Field(
        default=True,
        description="Whether self-service investigator registration is permitted"
    )
    DEFAULT_SIGNUP_ROLE: str = Field(
        default="analyst",
        description="Default least-privileged role for newly registered users (must never be administrator)"
    )

    # Passive Reconnaissance & Evidence Storage (Phase 4)
    EVIDENCE_STORAGE_PATH: str = Field(
        default="./evidence_storage",
        description="Filesystem root for storing raw forensic evidence files"
    )
    RDAP_BOOTSTRAP_URL: str = Field(
        default="https://rdap.org/domain",
        description="Bootstrap endpoint for RDAP domain lookups"
    )
    CRTSH_BASE_URL: str = Field(
        default="https://crt.sh",
        description="Public Certificate Transparency API endpoint"
    )
    THEHARVESTER_BIN: Optional[str] = Field(
        default=None,
        description="Optional absolute path or executable name for theHarvester"
    )
    RECON_TIMEOUT_SECONDS: int = Field(
        default=15,
        description="Network query timeout for individual passive reconnaissance collectors"
    )
    RECON_MAX_CONCURRENCY: int = Field(
        default=4,
        description="Maximum concurrent collectors running per investigation job"
    )

    # Active Reconnaissance & Nmap Execution (Phase 5)
    NMAP_BIN: Optional[str] = Field(
        default=None,
        description="Optional path to Nmap binary; auto-discovered from system PATH or common paths if None"
    )
    NMAP_DEFAULT_TIMEOUT_SECONDS: int = Field(
        default=120,
        description="Default timeout for active Nmap scan execution in seconds"
    )
    NMAP_MAX_CONCURRENCY: int = Field(
        default=2,
        description="Maximum concurrent active Nmap scans permitted across the application"
    )

    # Vulnerability Assessment & Greenbone/OpenVAS Integration (Phase 6)
    GVM_HOST: Optional[str] = Field(
        default=None,
        description="Hostname or IP address of the Greenbone / OpenVAS GMP service"
    )
    GVM_PORT: int = Field(
        default=9390,
        description="TLS port for Greenbone GMP service (default: 9390)"
    )
    GVM_UNIX_SOCKET: Optional[str] = Field(
        default=None,
        description="Path to Greenbone gvmd Unix domain socket (e.g. /run/gvmd/gvmd.sock)"
    )
    GVM_USERNAME: Optional[str] = Field(
        default=None,
        description="Greenbone administrative/service username"
    )
    GVM_PASSWORD: Optional[str] = Field(
        default=None,
        description="Greenbone service password (read from secret environment variable)"
    )
    GVM_TIMEOUT_SECONDS: int = Field(
        default=180,
        description="Network query and connection timeout for Greenbone GMP requests in seconds"
    )
    GVM_POLL_INTERVAL_SECONDS: int = Field(
        default=5,
        description="Polling frequency in seconds when monitoring Greenbone scan tasks"
    )
    GVM_MAX_POLL_ATTEMPTS: int = Field(
        default=60,
        description="Maximum polling cycles before timing out a running Greenbone assessment task"
    )
    GVM_TLS_VERIFY: bool = Field(
        default=True,
        description="Enforce TLS certificate verification when connecting to Greenbone over TLS"
    )

    @field_validator("DEBUG", mode="before")
    @classmethod
    def set_debug_mode(cls, v, values):
        # Default debug to True only in development mode if not explicitly set
        if v is None:
            return values.data.get("APP_ENV") == "development"
        return v

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_production_secret(cls, v: str, info):
        env = info.data.get("APP_ENV")
        if env == "production":
            if not v or "dev-insecure" in v or len(v) < 32:
                raise ValueError(
                    "CRITICAL: Production deployment requires a secure, high-entropy SECRET_KEY (min 32 chars). "
                    "Generate via: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
        return v

    @field_validator("DEBUG")
    @classmethod
    def validate_production_debug(cls, v: bool, info):
        env = info.data.get("APP_ENV")
        if env == "production" and v is True:
            raise ValueError("CRITICAL: DEBUG mode must be disabled (False) in production environments.")
        return v

    @property
    def is_sqlite(self) -> bool:
        """Returns True if database connection string targets SQLite."""
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_test(self) -> bool:
        return self.APP_ENV == "test"

    @property
    def cookie_secure(self) -> bool:
        """Determines if cookies should be sent with Secure flag."""
        if self.SESSION_COOKIE_SECURE is not None:
            return self.SESSION_COOKIE_SECURE
        return self.is_production

    def __repr__(self) -> str:
        """Sanitized representation to prevent leaking secrets in logging."""
        return (
            f"<Settings app_name='{self.APP_NAME}' "
            f"env='{self.APP_ENV}' "
            f"debug={self.DEBUG} "
            f"db='{'sqlite' if self.is_sqlite else 'relational'}'>"
        )


@lru_cache()
def get_settings() -> Settings:
    """Returns singleton cached instance of application settings."""
    return Settings()


settings = get_settings()

