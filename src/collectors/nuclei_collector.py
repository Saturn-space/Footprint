"""
FootprintIQ - ProjectDiscovery Nuclei Collector
Executes real, policy-governed Nuclei templates via shell=False subprocess,
parses JSONL results into normalized vulnerability findings, archives raw
evidence into SeaweedFS, and enforces fail-closed TargetAuthorizer scope rules.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from src.authorization.target_authorizer import TargetAuthorizer, TargetAuthorizationError
from src.services.nuclei_policy_service import (
    NucleiPolicyService,
    resolve_templates_dir,
)
from src.storage.seaweedfs_client import SeaweedFSClient

logger = logging.getLogger("FootprintIQ.NucleiCollector")

_BINARY_CANDIDATES = (
    os.getenv("NUCLEI_BINARY", "").strip(),
    "/usr/bin/nuclei",
    "/usr/local/bin/nuclei",
    shutil.which("nuclei") or "",
)

_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
    "informational": "Informational",
    "unknown": "Informational",
}

_VERSION_RE = re.compile(r"v?\d+\.\d+\.\d+")


def resolve_nuclei_binary() -> Optional[str]:
    """Locates the installed Nuclei executable without relying on a shell."""
    for cand in _BINARY_CANDIDATES:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    found = shutil.which("nuclei")
    if found and os.path.isfile(found) and os.access(found, os.X_OK):
        return found
    return None


class NucleiCollector:
    """Real ProjectDiscovery Nuclei scanner with strict safety policies & SeaweedFS evidence."""

    def __init__(
        self,
        binary_path: Optional[str] = None,
        templates_dir: Optional[str] = None,
        storage: Optional[SeaweedFSClient] = None,
        authorizer: Optional[TargetAuthorizer] = None,
    ):
        self.binary_path = binary_path or resolve_nuclei_binary()
        self.templates_dir = resolve_templates_dir(templates_dir)
        self.storage = storage or SeaweedFSClient()
        self.authorizer = authorizer or TargetAuthorizer()
        self._cached_version: Optional[str] = None

    def get_version(self) -> Optional[str]:
        """Reads the local Nuclei binary version cleanly."""
        if self._cached_version:
            return self._cached_version
        if not self.binary_path:
            return None
        try:
            proc = subprocess.run(
                [self.binary_path, "-duc", "-version"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            combined = f"{proc.stdout}\n{proc.stderr}"
            m = _VERSION_RE.search(combined)
            if m:
                self._cached_version = m.group(0)
                return self._cached_version
        except Exception as exc:
            logger.debug(f"Nuclei version probe notice: {exc}")
        return None

    def check_readiness(self) -> Dict[str, Any]:
        """Returns live operational readiness facts for Nuclei binary and templates."""
        binary = self.binary_path or resolve_nuclei_binary()
        catalog = NucleiPolicyService.inspect_templates_catalog(self.templates_dir)
        version = self.get_version() if binary else None
        ready = bool(binary and catalog.get("installed"))

        reasons: List[str] = []
        if not binary:
            reasons.append("Nuclei executable was not found on this system.")
        if not catalog.get("installed"):
            reasons.append("Nuclei template repository is missing or empty.")

        return {
            "available": bool(binary),
            "ready": ready,
            "status": "Operational" if ready else "Unavailable",
            "binary_path": binary,
            "version": version or ("Installed" if binary else "Not Installed"),
            "templates_dir": catalog.get("templates_dir"),
            "templates_installed": bool(catalog.get("installed")),
            "templates_count": int(catalog.get("total_templates") or 0),
            "template_categories": catalog.get("categories") or {},
            "profiles": NucleiPolicyService.list_profiles(),
            "reason": None if ready else "; ".join(reasons),
        }

    def run_scan(
        self,
        target: str,
        investigation_id: str,
        scan_id: Optional[str] = None,
        profile: str = "http-security",
        severities: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        template_ids: Optional[List[str]] = None,
        discovered_ports: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 180,
        rate_limit: int = 30,
        concurrency: int = 10,
        cancel_event: Optional[threading.Event] = None,
        repo: Any = None,
        authorization_profile: str = "lab-basic",
    ) -> Dict[str, Any]:
        """
        Validates target scope, runs policy-governed Nuclei subprocess (shell=False),
        archives JSONL artifact in SeaweedFS, and returns normalized DB-ready findings.
        """
        readiness = self.check_readiness()
        if not readiness.get("ready"):
            return {
                "status": "FAILED",
                "target": target,
                "error": readiness.get("reason") or "Nuclei scanner is unavailable.",
                "findings": [],
                "targets_scanned": [],
                "raw_records_count": 0,
            }

        auth_target = NucleiPolicyService.normalize_target_for_auth(target)
        try:
            auth_rec = self.authorizer.authorize_target(
                auth_target,
                profile=authorization_profile,
                investigation_id=investigation_id if repo is not None else None,
                repo=repo,
            )
            if not auth_rec.authorized:
                raise TargetAuthorizationError(
                    getattr(auth_rec, "failure_reason", f"Target '{auth_target}' is not authorized.")
                )
        except TargetAuthorizationError:
            raise

        target_urls = NucleiPolicyService.build_target_urls(
            target,
            discovered_ports=discovered_ports,
            profile=NucleiPolicyService.validate_profile(profile),
        )

        safe_timeout = max(15, min(int(timeout or 180), 900))
        with tempfile.TemporaryDirectory(prefix="fiq_nuclei_") as tmpdir:
            jsonl_path = os.path.join(tmpdir, "nuclei_results.jsonl")
            targets_file = os.path.join(tmpdir, "targets.txt")
            with open(targets_file, "w", encoding="utf-8") as tf:
                tf.write("\n".join(target_urls) + "\n")

            argv, applied_policy = NucleiPolicyService.build_cli_arguments(
                binary_path=readiness["binary_path"],
                target_urls=target_urls,
                jsonl_output_path=jsonl_path,
                target_list_path=targets_file if len(target_urls) > 1 else None,
                profile=profile,
                severities=severities,
                tags=tags,
                template_ids=template_ids,
                templates_dir=readiness.get("templates_dir"),
                rate_limit=rate_limit,
                concurrency=concurrency,
            )

            proc = subprocess.Popen(
                argv,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            started = time.monotonic()
            timed_out = False
            cancelled = False
            stdout_data = ""
            stderr_data = ""

            try:
                while proc.poll() is None:
                    if cancel_event is not None and cancel_event.is_set():
                        cancelled = True
                        proc.terminate()
                        break
                    if (time.monotonic() - started) > safe_timeout:
                        timed_out = True
                        proc.terminate()
                        break
                    time.sleep(0.25)

                try:
                    stdout_data, stderr_data = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout_data, stderr_data = proc.communicate(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                raise
            elapsed_seconds = round(max(0.0, time.monotonic() - started), 2)
            rc = proc.returncode
            stderr_excerpt = (stderr_data or "").strip()[:500] or None

            safe_cmd_summary = (
                f"nuclei -profile {applied_policy.get('profile', profile)} "
                f"-rl {applied_policy.get('rate_limit', rate_limit)} "
                f"-c {applied_policy.get('concurrency', concurrency)} "
                f"(targets={len(target_urls)}, timeout={safe_timeout}s)"
            )

            if cancelled:
                return {
                    "status": "CANCELLED",
                    "target": target,
                    "targets_scanned": target_urls,
                    "applied_policy": applied_policy,
                    "duration_seconds": elapsed_seconds,
                    "timeout_seconds": safe_timeout,
                    "timed_out": False,
                    "returncode": rc,
                    "error": "Nuclei scan cancelled by user request.",
                    "findings": [],
                    "raw_records_count": 0,
                    "execution_meta": {
                        "scanner": "nuclei",
                        "profile": applied_policy.get("profile", profile),
                        "duration_seconds": elapsed_seconds,
                        "timeout_seconds": safe_timeout,
                        "timed_out": False,
                        "returncode": rc,
                        "command_summary": safe_cmd_summary,
                        "targets_scanned_count": len(target_urls),
                        "stderr_excerpt": stderr_excerpt,
                        "raw_records_count": 0,
                        "parsed_findings_count": 0,
                        "parse_errors_count": 0,
                        "incomplete_reason": "Cancelled by operator",
                    },
                }

            # Read JSONL output cleanly (even partial findings on timeout if present)
            jsonl_bytes = b""
            if os.path.isfile(jsonl_path):
                with open(jsonl_path, "rb") as jf:
                    jsonl_bytes = jf.read()
            elif stdout_data.strip():
                jsonl_bytes = stdout_data.encode("utf-8", errors="replace")

            jsonl_text = jsonl_bytes.decode("utf-8", errors="replace")

        evidence_meta: Optional[Dict[str, Any]] = None
        evidence_ref = f"nuclei:{applied_policy['profile']}"
        if jsonl_bytes:
            fname = f"nuclei_{scan_id or 'scan'}_{applied_policy['profile']}.jsonl"
            try:
                evidence_meta = self.storage.upload_content(
                    content=jsonl_bytes,
                    file_name=fname,
                    investigation_id=investigation_id,
                    evidence_type="nuclei_jsonl",
                    content_type="application/x-ndjson",
                )
                evidence_ref = evidence_meta.get("seaweed_fid") or evidence_meta.get("file_name") or evidence_ref
            except Exception as store_err:
                logger.warning(f"Failed archiving Nuclei JSONL to SeaweedFS: {store_err}")

        parsed_findings, raw_count, parse_errors_count = self.parse_jsonl_with_stats(
            jsonl_text,
            default_target=auth_target,
            investigation_id=investigation_id,
            scan_id=scan_id,
            evidence_reference=evidence_ref,
        )

        incomplete_reason: Optional[str] = None
        skipped_checks: List[str] = []
        if timed_out:
            incomplete_reason = (
                f"Timeout reached at {safe_timeout}s during profile '{applied_policy.get('profile', profile)}' "
                f"across {len(target_urls)} target URL(s); remaining template subdirectories/checks did not finish."
            )
            subdirs = applied_policy.get("template_subdirs") or []
            if subdirs:
                skipped_checks.append(
                    f"Late template phases in profile '{applied_policy.get('profile', profile)}' "
                    f"({', '.join(subdirs)}) may be incomplete after {elapsed_seconds}s timeout."
                )
        elif rc not in (0, None):
            incomplete_reason = stderr_excerpt or f"Nuclei exited unexpectedly with return code {rc}."

        exec_meta = {
            "scanner": "nuclei",
            "profile": applied_policy.get("profile", profile),
            "template_subdirs": applied_policy.get("template_subdirs", []),
            "severities": applied_policy.get("severities", []),
            "duration_seconds": elapsed_seconds,
            "timeout_seconds": safe_timeout,
            "timed_out": timed_out,
            "returncode": rc,
            "command_summary": safe_cmd_summary,
            "targets_scanned_count": len(target_urls),
            "targets_scanned": target_urls[:20],
            "stderr_excerpt": stderr_excerpt,
            "raw_records_count": raw_count,
            "parsed_findings_count": len(parsed_findings),
            "parse_errors_count": parse_errors_count,
            "incomplete_reason": incomplete_reason,
            "skipped_checks": skipped_checks,
        }

        if timed_out and not parsed_findings:
            return {
                "status": "TIMEOUT",
                "target": target,
                "targets_scanned": target_urls,
                "applied_policy": applied_policy,
                "duration_seconds": elapsed_seconds,
                "timeout_seconds": safe_timeout,
                "timed_out": True,
                "returncode": rc,
                "error": f"Nuclei execution timed out after {safe_timeout}s ({elapsed_seconds}s elapsed) with 0 findings recorded.",
                "findings": [],
                "raw_records_count": 0,
                "evidence": evidence_meta,
                "errors": [incomplete_reason] if incomplete_reason else [],
                "execution_meta": exec_meta,
            }

        if rc not in (0, None) and not parsed_findings and not timed_out:
            err_msg = stderr_excerpt or f"Nuclei exited with code {rc}."
            return {
                "status": "FAILED",
                "target": target,
                "targets_scanned": target_urls,
                "applied_policy": applied_policy,
                "duration_seconds": elapsed_seconds,
                "timeout_seconds": safe_timeout,
                "timed_out": False,
                "returncode": rc,
                "error": err_msg[:400],
                "findings": [],
                "raw_records_count": 0,
                "evidence": evidence_meta,
                "errors": [err_msg[:400]],
                "execution_meta": exec_meta,
            }

        is_partial = timed_out or (rc not in (0, None))
        status_out = "PARTIAL" if is_partial else "COMPLETED"
        errors_out: List[str] = [incomplete_reason] if incomplete_reason else []

        return {
            "status": status_out,
            "target": target,
            "targets_scanned": target_urls,
            "applied_policy": applied_policy,
            "duration_seconds": elapsed_seconds,
            "timeout_seconds": safe_timeout,
            "timed_out": timed_out,
            "returncode": rc,
            "findings": parsed_findings,
            "raw_records_count": raw_count,
            "evidence": evidence_meta,
            "error": incomplete_reason,
            "errors": errors_out,
            "skipped_checks": skipped_checks,
            "execution_meta": exec_meta,
        }

    @classmethod
    def parse_jsonl_output(
        cls,
        jsonl_text: str,
        default_target: str,
        investigation_id: str,
        scan_id: Optional[str] = None,
        evidence_reference: str = "nuclei_jsonl",
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Parses Nuclei JSONL lines into normalized, deduplicated FootprintIQ findings."""
        findings, raw_count, _ = cls.parse_jsonl_with_stats(
            jsonl_text=jsonl_text,
            default_target=default_target,
            investigation_id=investigation_id,
            scan_id=scan_id,
            evidence_reference=evidence_reference,
        )
        return findings, raw_count

    @classmethod
    def parse_jsonl_with_stats(
        cls,
        jsonl_text: str,
        default_target: str,
        investigation_id: str,
        scan_id: Optional[str] = None,
        evidence_reference: str = "nuclei_jsonl",
    ) -> Tuple[List[Dict[str, Any]], int, int]:
        """Parses Nuclei JSONL lines into normalized findings plus raw & parse-error counts."""
        findings: List[Dict[str, Any]] = []
        seen_keys = set()
        raw_count = 0
        parse_errors = 0

        for line in (jsonl_text or "").splitlines():
            raw_line = line.strip()
            if not raw_line:
                continue
            try:
                rec = json.loads(raw_line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if not isinstance(rec, dict) or not (rec.get("template-id") or rec.get("templateID")):
                parse_errors += 1
                continue

            raw_count += 1
            finding = cls._normalize_jsonl_record(
                rec,
                default_target=default_target,
                investigation_id=investigation_id,
                scan_id=scan_id,
                evidence_reference=evidence_reference,
            )
            dedup_key = (
                finding.get("scanner_vt_id"),
                finding.get("target_ip"),
                finding.get("port"),
                finding.get("title"),
                finding.get("_matched_at") or "",
            )
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            finding.pop("_matched_at", None)
            findings.append(finding)

        return findings, raw_count, parse_errors

    @staticmethod
    def _normalize_jsonl_record(
        rec: Dict[str, Any],
        default_target: str,
        investigation_id: str,
        scan_id: Optional[str],
        evidence_reference: str,
    ) -> Dict[str, Any]:
        info = rec.get("info") if isinstance(rec.get("info"), dict) else {}
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}

        template_id = str(rec.get("template-id") or rec.get("templateID") or "nuclei-check")
        matcher_name = str(rec.get("matcher-name") or rec.get("matcher_name") or "").strip()
        raw_name = str(info.get("name") or template_id)
        title = f"{raw_name} ({matcher_name})" if matcher_name else raw_name

        raw_sev = str(info.get("severity") or "info").strip().lower()
        severity = _SEVERITY_MAP.get(raw_sev, "Informational")

        matched_at = str(rec.get("matched-at") or rec.get("url") or rec.get("host") or default_target)
        parsed_url = urlparse(matched_at) if "://" in matched_at else None

        host_val = str(
            rec.get("ip")
            or (parsed_url.hostname if parsed_url and parsed_url.hostname else None)
            or rec.get("host")
            or default_target
        ).strip()
        hostname_val = str(
            (parsed_url.hostname if parsed_url and parsed_url.hostname else None)
            or rec.get("host")
            or default_target
        ).strip()

        port_val: Optional[int] = None
        raw_port = rec.get("port")
        if raw_port is not None and str(raw_port).isdigit():
            p_int = int(str(raw_port))
            port_val = p_int if 1 <= p_int <= 65535 else None
        elif parsed_url and parsed_url.port and 1 <= int(parsed_url.port) <= 65535:
            port_val = int(parsed_url.port)
        elif parsed_url and parsed_url.scheme == "https":
            port_val = 443
        elif parsed_url and parsed_url.scheme == "http":
            port_val = 80

        proto_type = str(rec.get("scheme") or rec.get("type") or "tcp").lower()
        service_name = "https" if proto_type in ("https", "ssl") else (
            "http" if proto_type == "http" else proto_type
        )

        raw_cve = classification.get("cve-id")
        cve_str: Optional[str] = None
        if isinstance(raw_cve, list):
            clean_cves = [str(c).strip().upper() for c in raw_cve if c]
            cve_str = ", ".join(clean_cves[:5]) if clean_cves else None
        elif isinstance(raw_cve, str) and raw_cve.strip():
            cve_str = raw_cve.strip().upper()

        cvss_raw = classification.get("cvss-score")
        try:
            cvss_cand = float(cvss_raw) if cvss_raw is not None and str(cvss_raw).strip() != "" else None
            cvss_score = cvss_cand if (cvss_cand is not None and 0.0 <= cvss_cand <= 10.0) else None
        except (TypeError, ValueError):
            cvss_score = None

        extracted = rec.get("extracted-results") or []
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        desc_parts = [str(info.get("description") or "").strip()]
        desc_parts.append(f"Matched endpoint: {matched_at}.")
        if matcher_name:
            desc_parts.append(f"Matcher: {matcher_name}.")
        if "matcher-status" in rec:
            desc_parts.append(f"Scanner matcher-status: {bool(rec.get('matcher-status'))}.")
        epss_val = classification.get("epss-score")
        if epss_val is not None:
            desc_parts.append(f"EPSS score: {epss_val}.")
        if rec.get("curl-command"):
            desc_parts.append("Evidence includes non-destructive automated request/response probe (independent exploit verification not yet performed).")
        if extracted:
            sample = ", ".join(str(x) for x in extracted[:5])
            desc_parts.append(f"Extracted evidence: {sample}.")
        cwe_list = classification.get("cwe-id")
        if isinstance(cwe_list, list) and cwe_list:
            desc_parts.append(f"Classification: {', '.join(str(x).upper() for x in cwe_list[:3])}.")
        description = " ".join(p for p in desc_parts if p).strip()

        remediation = str(info.get("remediation") or "").strip()
        if not remediation:
            if "headers" in tags or "header" in title.lower():
                remediation = (
                    "Configure defensive HTTP security headers (Strict-Transport-Security, "
                    "Content-Security-Policy, X-Frame-Options, Referrer-Policy, Permissions-Policy) "
                    "and validate SameSite/Secure/HttpOnly cookie flags."
                )
            elif "ssl" in tags or "tls" in tags or proto_type == "ssl":
                remediation = (
                    "Enforce TLS 1.2/1.3 with strong AEAD cipher suites and deploy a valid CA-signed certificate "
                    "matching the target hostname."
                )
            elif cve_str:
                remediation = (
                    f"Apply vendor security patches addressing {cve_str} and restrict unnecessary exposure "
                    f"of the vulnerable endpoint ({matched_at})."
                )
            elif "panel" in tags:
                remediation = (
                    f"Restrict network access to the exposed administrative interface ({matched_at}) via VPN, "
                    "IP allowlisting, and strong multi-factor authentication."
                )
            else:
                remediation = (
                    f"Review template finding '{template_id}' on {matched_at}, verify configuration hardening, "
                    "and disable unnecessary endpoints or disclosure responses."
                )

        if cve_str or severity in ("Critical", "High", "Medium"):
            confidence = 0.90 if cve_str else 0.85
        else:
            confidence = 0.78

        id_seed = f"{investigation_id}|{scan_id or ''}|{host_val}|{port_val}|{template_id}|{matcher_name}|{matched_at}"
        fid_hash = hashlib.sha256(id_seed.encode("utf-8")).hexdigest()[:12].upper()

        return {
            "finding_id": f"NUC-{fid_hash}",
            "investigation_id": investigation_id,
            "scan_id": scan_id,
            "target_ip": host_val,
            "hostname": hostname_val,
            "port": port_val,
            "protocol": "tcp",
            "service": service_name,
            "service_version": None,
            "title": title[:250],
            "description": description[:2000],
            "cve_identifiers": cve_str,
            "cvss_score": cvss_score,
            "severity": severity,
            "confidence": confidence,
            "detection_source": "nuclei",
            "scanner_vt_id": template_id,
            "remediation": remediation[:1500],
            "evidence_reference": evidence_reference,
            "verification_status": "Observed",
            "_matched_at": matched_at,
        }
