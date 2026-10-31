"""Tool availability and capability detection for Nmap executable."""

import os
import re
import shutil
import subprocess
from typing import Dict, Any, Optional, List
import logging

from app.config import get_settings

logger = logging.getLogger("footprintiq.nmap.detector")

# Common fallback paths on Windows and Unix-like OSes
WELL_KNOWN_NMAP_PATHS = [
    r"E:\asipali\Nmap\nmap.exe",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/homebrew/bin/nmap",
]


class NmapDetector:
    """Discovers, verifies invocation permissions, and inspects version of Nmap."""

    def __init__(self, binary_override: Optional[str] = None):
        self._binary_override = binary_override

    def resolve_binary_path(self) -> Optional[str]:
        """Resolves the executable path from configuration, system PATH, or common locations."""
        settings = get_settings()

        # 1. Constructor override (used primarily for testing)
        candidates = []
        if self._binary_override:
            candidates.append(self._binary_override)

        # 2. Trusted application configuration
        if settings.NMAP_BIN:
            candidates.append(settings.NMAP_BIN)

        # 3. System PATH
        path_binary = shutil.which("nmap")
        if path_binary:
            candidates.append(path_binary)

        # 4. Well-known operating system locations
        candidates.extend(WELL_KNOWN_NMAP_PATHS)

        for candidate in candidates:
            if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return os.path.abspath(candidate)

        return None

    def check_availability(self) -> Dict[str, Any]:
        """Performs a safe, non-scanning invocation of Nmap (--version) to test availability."""
        binary_path = self.resolve_binary_path()
        if not binary_path:
            return {
                "is_available": False,
                "version": None,
                "binary_name": "nmap",
                "diagnostic_code": "NOT_INSTALLED",
                "message": "Nmap executable not found on system PATH or configured locations.",
                "capabilities": [],
                "error": "BinaryNotFound",
            }

        try:
            # Safe invocation without shell=True
            proc = subprocess.run(
                [binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if proc.returncode != 0:
                logger.warning(
                    "Nmap --version returned non-zero exit code %d: %s",
                    proc.returncode,
                    proc.stderr.strip() or proc.stdout.strip(),
                )
                return {
                    "is_available": False,
                    "version": None,
                    "binary_name": os.path.basename(binary_path),
                    "diagnostic_code": "INVOCATION_FAILED",
                    "message": f"Nmap exited with code {proc.returncode}",
                    "capabilities": [],
                    "error": proc.stderr.strip() or "NonZeroExit",
                }

            stdout = proc.stdout
            # Example stdout: "Nmap version 7.98 ( https://nmap.org )\nPlatform: ..."
            version_match = re.search(r"Nmap version\s+([0-9]+(?:\.[0-9]+)*[a-zA-Z0-9_-]*)", stdout, re.IGNORECASE)
            version = version_match.group(1) if version_match else "unknown"

            # Parse platform if present
            platform_match = re.search(r"Platform:\s+([^\r\n]+)", stdout)
            platform_str = platform_match.group(1) if platform_match else None

            return {
                "is_available": True,
                "version": version,
                "platform": platform_str,
                "binary_name": os.path.basename(binary_path),
                "diagnostic_code": "READY",
                "message": f"Nmap {version} ready for active reconnaissance.",
                "capabilities": [
                    "tcp_connect_scan",
                    "service_detection",
                    "timing_control",
                    "xml_output",
                ],
                "error": None,
            }

        except PermissionError as pe:
            logger.error("Permission denied when invoking Nmap binary: %s", pe)
            return {
                "is_available": False,
                "version": None,
                "binary_name": os.path.basename(binary_path),
                "diagnostic_code": "PERMISSION_DENIED",
                "message": "Permission denied when attempting to execute Nmap.",
                "capabilities": [],
                "error": str(pe),
            }
        except subprocess.TimeoutExpired:
            logger.error("Timeout checking Nmap availability via --version")
            return {
                "is_available": False,
                "version": None,
                "binary_name": os.path.basename(binary_path),
                "diagnostic_code": "TIMEOUT",
                "message": "Nmap invocation timed out.",
                "capabilities": [],
                "error": "ExecutionTimeout",
            }
        except Exception as exc:
            logger.exception("Unexpected error while checking Nmap availability: %s", exc)
            return {
                "is_available": False,
                "version": None,
                "binary_name": os.path.basename(binary_path),
                "diagnostic_code": "UNEXPECTED_ERROR",
                "message": f"Diagnostic error: {type(exc).__name__}",
                "capabilities": [],
                "error": str(exc),
            }


_detector_instance: Optional[NmapDetector] = None


def get_nmap_detector() -> NmapDetector:
    """Returns singleton NmapDetector instance."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = NmapDetector()
    return _detector_instance
