"""
OSINT-RECON Target Authorization Package
"""
from src.authorization.target_authorizer import (
    TargetAuthorizer,
    TargetAuthorizationError,
    TargetSyntaxError
)

__all__ = ["TargetAuthorizer", "TargetAuthorizationError", "TargetSyntaxError"]

