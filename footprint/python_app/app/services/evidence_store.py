"""Forensic evidence storage service with path traversal protection and integrity verification."""

import os
import json
import hashlib
from pathlib import Path
from typing import Tuple, Union, Optional
from app.config import get_settings


class EvidenceStore:
    """Manages secure filesystem persistence and retrieval of raw OSINT collection evidence."""

    def __init__(self, base_path: Optional[str] = None):
        settings = get_settings()
        self.base_dir = Path(base_path or settings.EVIDENCE_STORAGE_PATH).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_investigation_dir(self, investigation_id: str) -> Path:
        """Resolves investigation storage directory, strictly preventing path traversal."""
        if not investigation_id or ".." in investigation_id or "/" in investigation_id or "\\" in investigation_id:
            raise ValueError(f"Path traversal or invalid characters detected in investigation ID: {investigation_id}")

        safe_id = "".join(c for c in investigation_id if c.isalnum() or c in ("-", "_"))
        if not safe_id:
            raise ValueError("Invalid investigation ID for evidence storage.")

        target_dir = (self.base_dir / safe_id).resolve()
        if not target_dir.is_relative_to(self.base_dir):
            raise ValueError(f"Path traversal detected for investigation ID: {investigation_id}")

        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def store_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
        source_type: str,
        content: Union[str, bytes, dict, list],
    ) -> Tuple[str, str, int]:
        """Saves raw evidence to disk.

        Returns:
            (relative_file_path, content_sha256_hash, content_size_bytes)
        """
        inv_dir = self._get_investigation_dir(investigation_id)

        safe_evidence_id = "".join(c for c in evidence_id if c.isalnum() or c in ("-", "_"))
        safe_source = "".join(c for c in source_type.lower() if c.isalnum() or c in ("-", "_"))

        if isinstance(content, (dict, list)):
            encoded_bytes = json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
            extension = "json"
        elif isinstance(content, str):
            encoded_bytes = content.encode("utf-8")
            extension = "txt"
        elif isinstance(content, bytes):
            encoded_bytes = content
            extension = "bin"
        else:
            encoded_bytes = str(content).encode("utf-8")
            extension = "txt"

        filename = f"{safe_evidence_id}_{safe_source}.raw.{extension}"
        file_path = (inv_dir / filename).resolve()

        if not file_path.is_relative_to(inv_dir):
            raise ValueError("Path traversal detected in evidence filename construction.")

        # Compute SHA-256 hash
        content_hash = hashlib.sha256(encoded_bytes).hexdigest()
        content_size = len(encoded_bytes)

        # Write to disk
        file_path.write_bytes(encoded_bytes)

        # Return relative path for database storage (no absolute server paths exposed)
        rel_path = file_path.relative_to(self.base_dir).as_posix()
        return rel_path, content_hash, content_size

    def read_evidence(self, relative_path: str) -> Tuple[bytes, str]:
        """Reads raw evidence from disk and verifies integrity against computed SHA-256 hash."""
        file_path = (self.base_dir / relative_path).resolve()
        if not file_path.is_relative_to(self.base_dir):
            raise ValueError("Path traversal detected in relative evidence path.")

        if not file_path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {relative_path}")

        content_bytes = file_path.read_bytes()
        computed_hash = hashlib.sha256(content_bytes).hexdigest()
        return content_bytes, computed_hash


_default_store = None


def get_evidence_store() -> EvidenceStore:
    """Returns singleton evidence store instance."""
    global _default_store
    if _default_store is None:
        _default_store = EvidenceStore()
    return _default_store
