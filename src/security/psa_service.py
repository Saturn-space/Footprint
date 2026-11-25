"""
FootprintIQ - Privilege Consent & Authorization (PSA) Service
Handles investigator identity re-verification, ephemeral cryptographic scan tickets,
and strict lifecycle enforcement (single-use, 5-minute TTL, non-transferable).

Security Principles:
1. Never prompts for or accepts Kali root password.
2. Never sends investigator password to Kali or any external process.
3. Passwords are never stored in plaintext, logs, arguments, or execution configs.
4. Ephemeral authorization tickets are cryptographically random, single-use, and expire in 300 seconds.
"""

import time
import secrets
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta

from src.services.auth_service import verify_password
from src.db.repository import FootprintIQRepository

logger = logging.getLogger("FootprintIQ.PSAService")

DEFAULT_PSA_TICKET_TTL_SECONDS = 300  # 5 minutes


class PSATicketError(Exception):
    """Base exception for PSA ticket errors."""
    pass


class PSAIdentityVerificationError(PSATicketError):
    """Raised when investigator password verification fails."""
    pass


class PSATicketExpiredOrInvalidError(PSATicketError):
    """Raised when PSA ticket is missing, expired, already consumed, or invalid."""
    pass


class PSATicket:
    def __init__(
        self,
        token: str,
        user_id: int,
        username: str,
        recon_id: str,
        target: str,
        approved_operations: List[str],
        ttl_seconds: int = DEFAULT_PSA_TICKET_TTL_SECONDS
    ):
        self.token = token
        self.user_id = user_id
        self.username = username
        self.recon_id = recon_id
        self.target = target
        self.approved_operations = list(approved_operations)
        self.created_at = datetime.now(timezone.utc)
        self.expires_at = self.created_at + timedelta(seconds=ttl_seconds)
        self.consumed = False
        self.consumed_at: Optional[datetime] = None

    def is_valid(self, user_id: int, recon_id: str) -> Tuple[bool, Optional[str]]:
        now = datetime.now(timezone.utc)
        if self.consumed:
            return False, "Authorization ticket has already been used (single-use only)."
        if now > self.expires_at:
            return False, "Authorization ticket has expired (5-minute TTL exceeded). Re-authentication required."
        if int(self.user_id) != int(user_id):
            return False, "Authorization ticket user identity mismatch."
        if self.recon_id != recon_id:
            return False, "Authorization ticket campaign scope mismatch."
        return True, None

    def consume(self) -> None:
        self.consumed = True
        self.consumed_at = datetime.now(timezone.utc)


class PSAService:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(PSAService, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, repo: Optional[FootprintIQRepository] = None):
        if getattr(self, "_initialized", False):
            return
        self.repo = repo or FootprintIQRepository()
        self._tickets: Dict[str, PSATicket] = {}
        self._ticket_lock = threading.Lock()
        self._initialized = True

    def _purge_expired_tickets(self) -> None:
        now = datetime.now(timezone.utc)
        to_delete = [
            tok for tok, t in self._tickets.items()
            if now > (t.expires_at + timedelta(minutes=10))
        ]
        for tok in to_delete:
            self._tickets.pop(tok, None)

    def verify_identity_and_issue_ticket(
        self,
        current_user: Dict[str, Any],
        plain_password: str,
        recon_id: str,
        target: str,
        approved_operations: List[str],
        ttl_seconds: int = DEFAULT_PSA_TICKET_TTL_SECONDS
    ) -> Dict[str, Any]:
        """
        Re-verifies investigator identity against their stored FootprintIQ bcrypt hash.
        On success, generates an ephemeral, short-lived single-use authorization ticket.
        """
        username = current_user.get("username", "")
        user_id = current_user.get("id") or current_user.get("user_id")

        # Fetch fresh user record from repository to guarantee current hash
        db_user = self.repo.get_user_by_username(username)
        if not db_user:
            raise PSAIdentityVerificationError("User account not found.")

        hashed_password = db_user.get("hashed_password") or ""
        if not hashed_password or not verify_password(plain_password, hashed_password):
            logger.warning(f"PSA identity re-verification failed for user '{username}' on campaign '{recon_id}'.")
            raise PSAIdentityVerificationError("Invalid account credentials. Identity verification failed.")

        # Generate ticket token
        token = "psa_" + secrets.token_urlsafe(32)
        ticket = PSATicket(
            token=token,
            user_id=int(user_id),
            username=username,
            recon_id=recon_id,
            target=target,
            approved_operations=approved_operations,
            ttl_seconds=ttl_seconds
        )

        with self._ticket_lock:
            self._purge_expired_tickets()
            self._tickets[token] = ticket

        logger.info(f"PSA ticket issued for user '{username}' on campaign '{recon_id}' (expires: {ticket.expires_at.isoformat()}).")
        return {
            "ticket_token": token,
            "username": username,
            "recon_id": recon_id,
            "target": target,
            "approved_operations": approved_operations,
            "expires_at": ticket.expires_at.isoformat(),
            "ttl_seconds": ttl_seconds,
        }

    def validate_and_consume_ticket(
        self,
        token: str,
        user_id: int,
        recon_id: str,
    ) -> PSATicket:
        """
        Validates the ticket token, verifies user and campaign scope, and consumes it immediately.
        """
        if not token or not isinstance(token, str):
            raise PSATicketExpiredOrInvalidError("Privilege authorization ticket is missing or invalid.")

        with self._ticket_lock:
            ticket = self._tickets.get(token)
            if not ticket:
                raise PSATicketExpiredOrInvalidError("Privilege authorization ticket not found or already consumed.")

            is_valid, reason = ticket.is_valid(user_id=user_id, recon_id=recon_id)
            if not is_valid:
                raise PSATicketExpiredOrInvalidError(reason or "Privilege authorization ticket is invalid.")

            # Consume ticket immediately (single-use)
            ticket.consume()

        logger.info(f"PSA ticket {token[:12]}... successfully validated and consumed for user_id {user_id} on {recon_id}.")
        return ticket

    def peek_ticket(self, token: str) -> Optional[PSATicket]:
        """Inspects ticket without consuming it."""
        with self._ticket_lock:
            return self._tickets.get(token)
