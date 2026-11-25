"""
FootprintIQ - Privileged Execution Layer
Dedicated restricted wrapper executing approved security scanner binaries (Nmap)
with shell=False, strict argument allowlists, target validation, and honest failure capture.

Security Invariants:
1. shell=False is strictly enforced on all subprocess invocations.
2. Only approved binary paths (/usr/bin/nmap, /usr/local/bin/nmap, etc.) are executed.
3. Every argument is checked against an allowlist pattern; arbitrary flags or shell injection metacharacters are rejected.
4. Target is validated before execution.
5. Inability to elevate or scanner failures capture returncode and stderr honestly (Scenario E).
"""

import os
import re
import shlex
import shutil
import logging
import subprocess
from typing import List, Dict, Any, Optional, Tuple

from src.collectors.nmap_collector import (
    NmapCollectorResult,
    resolve_nmap_binary,
    detect_nmap_capabilities,
    compute_file_sha256,
)

logger = logging.getLogger("FootprintIQ.PrivilegedExecutor")

# Strict argument regex patterns allowlisted for privileged and unprivileged Nmap executions
ALLOWLISTED_ARG_PATTERNS = [
    re.compile(r"^-s[STVU]$"),                       # Scan types: -sS, -sT, -sV, -sU
    re.compile(r"^-sC$"),                            # Default scripts
    re.compile(r"^-O$"),                             # OS fingerprinting
    re.compile(r"^-Pn$"),                            # Skip ping
    re.compile(r"^-sn$"),                            # Ping only
    re.compile(r"^-PE$"),                            # ICMP echo ping
    re.compile(r"^-PR$"),                            # ARP discovery
    re.compile(r"^-PA[0-9,]*$"),                     # TCP ACK ping
    re.compile(r"^-p$"),                             # Port flag
    re.compile(r"^-p-$"),                            # All ports flag
    re.compile(r"^--top-ports$"),                    # Top ports flag
    re.compile(r"^[0-9]+$"),                         # Integer port or count
    re.compile(r"^[0-9]+-[0-9]+$"),                  # Port range e.g. 1-1024
    re.compile(r"^[TU0-9,-:]+$"),                    # Comma-separated or T:80,U:53 specs
    re.compile(r"^--exclude-ports$"),                # Exclude ports flag
    re.compile(r"^--version-intensity$"),            # Version intensity flag
    re.compile(r"^--script=[a-zA-Z0-9_-]+$"),         # Script flag
    re.compile(r"^-T[1-5]$"),                        # Timing profile
    re.compile(r"^-oX$"),                            # XML output flag
]

DANGEROUS_SHELL_CHARS = set(";&|`$><!*?()[]{}\n\r\t")


class PrivilegedExecutionError(Exception):
    """Raised when privileged execution parameters are invalid or execution fails."""
    pass


class PrivilegedExecutor:
    """
    Restricted execution gateway for privileged scanner invocations.
    """

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = resolve_nmap_binary(binary_path)

    @staticmethod
    def validate_command_arguments(args: List[str], target: str) -> None:
        """
        Validates argument list fail-closed against strict allowlist patterns.
        Rejects any dangerous shell characters or unexpected flags.
        """
        if not args or not isinstance(args, list):
            raise PrivilegedExecutionError("Command arguments must be a non-empty list.")

        for arg in args:
            if not isinstance(arg, str):
                raise PrivilegedExecutionError(f"Invalid non-string argument: {arg}")

            if any(ch in DANGEROUS_SHELL_CHARS for ch in arg):
                raise PrivilegedExecutionError(f"Disallowed metacharacter in scanner argument: {arg}")

            # Target argument validation
            if arg == target or os.path.isabs(arg):
                continue

            # Check if matches any allowlist pattern
            matched = any(pattern.fullmatch(arg) for pattern in ALLOWLISTED_ARG_PATTERNS)
            if not matched:
                raise PrivilegedExecutionError(f"Disallowed or unapproved Nmap argument: '{arg}'")

    @classmethod
    def can_elevate(cls, binary_path: str) -> Tuple[bool, str]:
        """
        Detects whether elevated raw-packet execution is permitted.
        Checks EUID == 0, Linux capabilities (cap_net_raw), or passwordless sudo.
        """
        caps = detect_nmap_capabilities(binary_path)
        if caps.get("has_raw_socket"):
            return True, "native_capability"

        # Check for non-interactive sudo support: sudo -n <binary_path> --version
        if shutil.which("sudo"):
            try:
                res = subprocess.run(
                    ["sudo", "-n", binary_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if res.returncode == 0:
                    return True, "sudo_nopasswd"
            except Exception:
                pass

        return False, "unprivileged_standard"

    def execute_privileged_nmap(
        self,
        command_args: List[str],
        target: str,
        timeout: int = 120,
        output_dir: Optional[str] = None,
        use_elevation: bool = True
    ) -> NmapCollectorResult:
        """
        Executes Nmap with verified allowlisted arguments using subprocess with shell=False.
        """
        self.validate_command_arguments(command_args, target)

        if not os.path.exists(self.binary_path):
            return NmapCollectorResult(
                command_list=[self.binary_path] + command_args,
                returncode=-1,
                stdout="",
                stderr=f"Nmap binary not found at '{self.binary_path}'",
                error_message=f"Nmap binary not found at '{self.binary_path}'"
            )

        # Output file paths
        xml_path = stdout_path = stderr_path = metadata_path = None
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            xml_path = os.path.join(output_dir, "nmap_scan.xml")
            stdout_path = os.path.join(output_dir, "nmap_stdout.txt")
            stderr_path = os.path.join(output_dir, "nmap_stderr.txt")
            metadata_path = os.path.join(output_dir, "scan_metadata.json")

        base_cmd: List[str]
        can_elev, elev_mode = self.can_elevate(self.binary_path)

        if use_elevation and elev_mode == "sudo_nopasswd":
            base_cmd = ["sudo", "-n", self.binary_path]
        else:
            base_cmd = [self.binary_path]

        full_cmd = base_cmd + list(command_args)
        if xml_path and "-oX" not in full_cmd:
            full_cmd.extend(["-oX", xml_path])
        if target not in full_cmd:
            full_cmd.append(target)

        import time
        start_time = time.time()
        try:
            logger.info(f"Executing scanner command safely (shell=False): {' '.join(full_cmd)}")
            proc = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False
            )
            duration = round(time.time() - start_time, 2)
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            rc = proc.returncode

            # Scenario E: Honest capture of failure
            err_msg = None
            if rc != 0:
                err_msg = f"Nmap exited with return code {rc}: {stderr.strip() or stdout.strip()}"
                logger.warning(err_msg)

            # Persist raw stdout/stderr
            if stdout_path:
                with open(stdout_path, "w", encoding="utf-8") as f:
                    f.write(stdout)
            if stderr_path:
                with open(stderr_path, "w", encoding="utf-8") as f:
                    f.write(stderr)

            # Check hashes
            file_hashes = {}
            if xml_path and os.path.exists(xml_path):
                file_hashes["xml"] = compute_file_sha256(xml_path)
            if stdout_path and os.path.exists(stdout_path):
                file_hashes["stdout"] = compute_file_sha256(stdout_path)

            return NmapCollectorResult(
                command_list=full_cmd,
                returncode=rc,
                stdout=stdout,
                stderr=stderr,
                xml_path=xml_path,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                metadata_path=metadata_path,
                duration_seconds=duration,
                file_hashes=file_hashes,
                error_message=err_msg
            )
        except subprocess.TimeoutExpired as exc:
            duration = round(time.time() - start_time, 2)
            timeout_msg = f"Nmap execution timed out after {timeout} seconds."
            logger.error(timeout_msg)
            return NmapCollectorResult(
                command_list=full_cmd,
                returncode=-1,
                stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
                stderr=timeout_msg,
                duration_seconds=duration,
                error_message=timeout_msg
            )
        except Exception as exc:
            duration = round(time.time() - start_time, 2)
            logger.error(f"Scanner execution exception: {exc}")
            return NmapCollectorResult(
                command_list=full_cmd,
                returncode=-1,
                stdout="",
                stderr=str(exc),
                duration_seconds=duration,
                error_message=f"Scanner execution failure: {str(exc)}"
            )
