"""theHarvester execution and output ingestion collector."""

import asyncio
import json
import os
import re
import shutil
import tempfile
from typing import Dict, Any, List, Optional

from app.config import settings
from app.services.collectors.base import BaseCollector, CollectorResult, DiscoveredFinding


class TheHarvesterCollector(BaseCollector):
    """Executes theHarvester OSINT tool via controlled subprocess and ingests findings."""

    name: str = "theharvester_collector"
    source_type: str = "THEHARVESTER"

    def __init__(self, binary_path: Optional[str] = None, timeout_seconds: Optional[int] = None):
        self.binary_path = binary_path or settings.THEHARVESTER_BIN
        self.timeout_seconds = timeout_seconds or settings.RECON_TIMEOUT_SECONDS

    def is_available(self) -> bool:
        """Checks if the configured theHarvester binary exists on the system PATH."""
        if not self.binary_path:
            return False
        return shutil.which(self.binary_path) is not None

    async def collect(self, target: str) -> CollectorResult:
        clean_target = target.strip().lower()
        if not clean_target:
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name="theharvester",
                target=target,
                status="FAILED",
                raw_content="",
                content_format="text",
                error_category="INVALID_TARGET",
                error_message="Empty domain target specified",
            )

        if not self.is_available():
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name="theharvester",
                target=clean_target,
                status="NOT_CONFIGURED",
                raw_content="",
                content_format="text",
                error_category="MISSING_EXECUTABLE",
                error_message=f"theHarvester binary '{self.binary_path}' is not installed or not found on PATH",
            )

        # Create a temporary directory to store output json
        temp_dir = tempfile.mkdtemp(prefix="fpt_theharvester_")
        out_base = os.path.join(temp_dir, "output")
        json_file = f"{out_base}.json"

        # Safe command arguments without shell interpolation
        cmd = [
            self.binary_path,
            "-d", clean_target,
            "-b", "all",
            "-f", out_base,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout_seconds,
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                return CollectorResult(
                    collector_name=self.name,
                    source_type=self.source_type,
                    source_name="theharvester",
                    target=clean_target,
                    status="FAILED",
                    raw_content="",
                    content_format="text",
                    error_category="SUBPROCESS_TIMEOUT",
                    error_message=f"theHarvester process timed out after {self.timeout_seconds} seconds",
                )

            stdout_text = stdout_data.decode("utf-8", errors="replace")
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            exit_code = proc.returncode

            # Check if JSON output file was produced
            findings: List[DiscoveredFinding] = []
            raw_data: Any = stdout_text
            content_format = "text"

            if os.path.exists(json_file):
                try:
                    with open(json_file, "r", encoding="utf-8") as f:
                        json_content = json.load(f)
                    raw_data = json_content
                    content_format = "json"
                    findings = self._parse_json_output(clean_target, json_content)
                except Exception:
                    # Fallback to stdout regex parsing if JSON file corrupt
                    findings = self._parse_stdout_text(clean_target, stdout_text)
            else:
                findings = self._parse_stdout_text(clean_target, stdout_text)

            status = "SUCCESS" if exit_code == 0 else ("PARTIAL" if findings else "FAILED")
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name="theharvester",
                target=clean_target,
                status=status,
                raw_content=raw_data,
                content_format=content_format,
                findings=findings,
                source_metadata={
                    "exit_code": exit_code,
                    "stderr_summary": stderr_text[:500] if stderr_text else None,
                    "findings_count": len(findings),
                },
                error_message=stderr_text[:500] if exit_code != 0 and not findings else None,
            )

        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name="theharvester",
                target=clean_target,
                status="FAILED",
                raw_content="",
                content_format="text",
                error_category="EXECUTION_ERROR",
                error_message=f"Subprocess invocation failed: {exc}",
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _parse_json_output(self, target: str, data: Dict[str, Any]) -> List[DiscoveredFinding]:
        findings: List[DiscoveredFinding] = []

        # Parse emails
        for email in data.get("emails", []):
            if isinstance(email, str) and "@" in email:
                findings.append(
                    DiscoveredFinding(
                        entity_type="EMAIL",
                        raw_value=email.strip().lower(),
                        metadata={"source": "theharvester_json"},
                    )
                )

        # Parse hosts / subdomains
        for host in data.get("hosts", []):
            host_str = host if isinstance(host, str) else str(host.get("host", ""))
            clean_host = host_str.strip().lower().rstrip(".")
            if not clean_host:
                continue
            entity_type = "SUBDOMAIN" if clean_host.endswith(f".{target}") and clean_host != target else "HOST"
            findings.append(
                DiscoveredFinding(
                    entity_type=entity_type,
                    raw_value=clean_host,
                    metadata={"source": "theharvester_json"},
                )
            )

        # Parse IPs
        for ip in data.get("ips", []):
            if isinstance(ip, str) and ip.strip():
                findings.append(
                    DiscoveredFinding(
                        entity_type="IP_ADDRESS",
                        raw_value=ip.strip(),
                        metadata={"source": "theharvester_json"},
                    )
                )

        return findings

    def _parse_stdout_text(self, target: str, stdout: str) -> List[DiscoveredFinding]:
        findings: List[DiscoveredFinding] = []
        seen = set()

        # Extract Emails
        email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        for email in re.findall(email_pattern, stdout):
            clean_email = email.lower().strip(".")
            if clean_email not in seen:
                seen.add(clean_email)
                findings.append(
                    DiscoveredFinding(
                        entity_type="EMAIL",
                        raw_value=clean_email,
                        metadata={"source": "theharvester_stdout"},
                    )
                )

        # Extract Hosts
        host_pattern = rf"(?:[a-zA-Z0-9_-]+\.)+{re.escape(target)}"
        for host in re.findall(host_pattern, stdout, re.IGNORECASE):
            clean_host = host.lower().strip(".")
            if clean_host not in seen:
                seen.add(clean_host)
                entity_type = "SUBDOMAIN" if clean_host != target else "DOMAIN"
                findings.append(
                    DiscoveredFinding(
                        entity_type=entity_type,
                        raw_value=clean_host,
                        metadata={"source": "theharvester_stdout"},
                    )
                )

        return findings
