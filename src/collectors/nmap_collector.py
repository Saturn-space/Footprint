"""
OSINT-RECON Nmap Active Reconnaissance Collector Module
Executes Nmap safely using subprocess argument lists with explicit timeouts,
evidence preservation, SHA256 checksum generation, and error boundary isolation.
"""

import os
import re
import shutil
import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

from src.schema import TargetAuthorizationRecord

# Supported controlled lab scanning profiles
SUPPORTED_PROFILES: Dict[str, Dict[str, Any]] = {
    "lab-basic": {
        "description": "Standard controlled TCP Connect scan with service/version detection (Top 100 ports).",
        "args": ["-sT", "-sV", "-Pn", "--top-ports", "100"]
    },
    "lab-safe-minimal": {
        "description": "Fast minimal TCP Connect scan covering top 10 standard infrastructure ports.",
        "args": ["-sT", "-sV", "-Pn", "-p", "21,22,23,25,80,443,445,3306,5432,8080"]
    },
    "lab-common-services": {
        "description": "Controlled scan covering common infrastructure and service ports without intrusive scripts.",
        "args": [
            "-sT", "-sV", "-Pn", "-p",
            "21,22,23,25,53,80,110,111,139,143,445,512,513,514,1099,1524,2049,2121,3306,3632,5432,5900,6000,6667,8009,8180"
        ]
    }
}

ALLOWED_TIMING_PROFILES = {"T1", "T2", "T3", "T4"}


def parse_and_validate_ports(port_spec: str) -> str:
    """
    Strictly validates and normalizes user-supplied custom port specifications
    such as '22,80,443,3306,8080' or '1-1024,8000-8100'.
    Rejects any non-numeric, shell metacharacters, or out-of-range port values.
    """
    if not port_spec or not isinstance(port_spec, str):
        raise ValueError("Custom port specification cannot be empty.")

    tokens = [t.strip() for t in port_spec.split(",") if t.strip()]
    if not tokens:
        raise ValueError("No valid ports provided in specification.")
    if len(tokens) > 200:
        raise ValueError("Too many individual port tokens (maximum 200 tokens).")

    normalized: List[str] = []
    for token in tokens:
        if re.fullmatch(r"\d{1,5}", token):
            p = int(token)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port out of valid 1-65535 range: {token}")
            normalized.append(str(p))
        elif re.fullmatch(r"\d{1,5}-\d{1,5}", token):
            start_s, end_s = token.split("-", 1)
            start_p, end_p = int(start_s), int(end_s)
            if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p):
                raise ValueError(f"Invalid port range: {token}")
            normalized.append(f"{start_p}-{end_p}")
        else:
            raise ValueError(
                f"Invalid port token '{token}'. Use comma-separated ports or ranges (e.g. '22,80,443,3306,8080' or '1-1024')."
            )

    return ",".join(normalized)


def detect_nmap_capabilities(binary_path: str) -> Dict[str, Any]:
    """
    Checks actual binary existence and runtime packet capabilities without assuming root.
    """
    exists = bool(binary_path and os.path.exists(binary_path))
    has_raw_socket = False
    if os.geteuid() == 0:
        has_raw_socket = True
    elif exists:
        try:
            res = subprocess.run(["getcap", binary_path], capture_output=True, text=True, timeout=3)
            out = res.stdout or ""
            if "cap_net_raw" in out:
                has_raw_socket = True
        except Exception:
            has_raw_socket = False

    return {
        "binary_found": exists,
        "binary_path": binary_path,
        "has_raw_socket": has_raw_socket,
        "privileges_note": (
            "Elevated raw-socket privileges active (SYN, UDP, OS fingerprinting available)."
            if has_raw_socket
            else "Running in standard user privilege mode: TCP Connect, service/version detection, ping discovery, and safe scripts are available; raw SYN/UDP/OS scans require elevated packet privileges."
        )
    }


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA256 hash of a file for integrity verification."""
    if not os.path.exists(filepath):
        return ""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class NmapCollectorResult:
    """Container for low-level Nmap execution outputs and evidence paths."""

    def __init__(
        self,
        command_list: List[str],
        returncode: int,
        stdout: str,
        stderr: str,
        xml_path: Optional[str] = None,
        stdout_path: Optional[str] = None,
        stderr_path: Optional[str] = None,
        metadata_path: Optional[str] = None,
        duration_seconds: float = 0.0,
        file_hashes: Optional[Dict[str, str]] = None,
        error_message: Optional[str] = None
    ):
        self.command_list = command_list
        self.command_str = " ".join(command_list)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.xml_path = xml_path
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        self.metadata_path = metadata_path
        self.duration_seconds = duration_seconds
        self.file_hashes = file_hashes or {}
        self.error_message = error_message


def resolve_nmap_binary(specified_path: Optional[str] = None) -> str:
    """Cross-platform binary resolution for Nmap across Linux and Windows."""
    if specified_path and os.path.exists(specified_path):
        return specified_path

    env_path = os.getenv("NMAP_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    which_path = shutil.which("nmap") or shutil.which("nmap.exe")
    if which_path:
        return which_path

    if os.name == "nt":
        for win_path in [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]:
            if os.path.isfile(win_path):
                return win_path

    if os.path.exists("/usr/bin/nmap"):
        return "/usr/bin/nmap"

    return "nmap"


class NmapCollector:
    """
    Executes controlled active Nmap reconnaissance with strict argument list isolation.
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        timeout: int = 120
    ):
        self.binary_path = resolve_nmap_binary(binary_path)
        self.timeout = timeout
        self.version = self._detect_version()
        self.capabilities = detect_nmap_capabilities(self.binary_path)

    def build_safe_custom_args(self, options: Dict[str, Any], allow_privileged: bool = False) -> List[str]:
        """
        Builds a strictly allowlisted Nmap argument list from validated UI/API options.
        Arbitrary command flags or shell syntax are strictly impossible here.
        """
        args: List[str] = []
        has_raw = self.capabilities.get("has_raw_socket", False) or allow_privileged

        # 1. Host discovery mode
        discovery = str(options.get("host_discovery", "skip_discovery") or "skip_discovery").strip().lower()
        ping_only = discovery in ("ping_only", "ping_discovery", "network_discovery", "ip_range_discovery")
        if ping_only:
            if discovery == "ping_discovery":
                args.extend(["-sn", "-PE"])
            elif discovery in ("network_discovery", "ip_range_discovery"):
                args.extend(["-sn", "-PE", "-PA22,80,443"])
            else:
                args.append("-sn")
        elif discovery == "tcp_ping":
            args.extend(["-PA22,80,443,3389", "-PE"])
        elif discovery == "arp_discovery":
            if not has_raw:
                raise ValueError("ARP host discovery requires elevated raw-socket privileges on this host.")
            args.append("-PR")
        elif discovery == "ping_sweep":
            args.extend(["-PE", "-PA80,443"])
        else:
            args.append("-Pn")

        # If discovery-only mode, omit port scan options cleanly
        if ping_only:
            timing = str(options.get("timing", "T3") or "T3").upper()
            if timing in ALLOWED_TIMING_PROFILES:
                args.append(f"-{timing}")
            return args

        # 2. Scan technique (TCP & UDP)
        port_mode = str(options.get("port_mode", "top_100") or "top_100").strip().lower()
        udp_custom_ports = (options.get("udp_custom_ports") or options.get("udp_ports") or "").strip()
        udp_mode = str(options.get("udp_port_mode", "none") or ("udp_common" if options.get("udp_scan") else "none")).strip().lower()
        udp_enabled = bool(options.get("udp_scan")) or (udp_mode not in ("", "none", "udp_none")) or (port_mode == "udp_only")

        tcp_type = str(options.get("tcp_scan_type", "tcp_connect") or "tcp_connect").strip().lower()
        if port_mode != "udp_only":
            if tcp_type == "tcp_syn":
                if not has_raw:
                    raise ValueError("TCP SYN stealth scan (-sS) requires elevated raw-socket privileges; choose TCP Connect (-sT) instead.")
                args.append("-sS")
            elif tcp_type == "tcp_connect":
                args.append("-sT")

        if udp_enabled:
            if not has_raw:
                raise ValueError("UDP scanning (-sU) requires elevated raw-socket privileges on this host.")
            args.append("-sU")

        # 3. Port selection (validated strictly)
        custom_ports = (options.get("custom_ports") or options.get("port_range") or "").strip()
        common_tcp = "21,22,23,25,53,80,110,111,135,139,143,443,445,512,513,514,993,995,1099,1433,1524,2049,2121,3306,3389,3632,5432,5900,6000,6379,6667,8009,8080,8180,8443,27017"

        port_specs: List[str] = []
        if port_mode == "udp_only":
            pass
        elif port_mode in ("custom", "port_range") or (custom_ports and port_mode not in ("top_100", "top_1000", "all_ports", "service_common", "udp_only")):
            normalized_ports = parse_and_validate_ports(custom_ports)
            if udp_enabled:
                port_specs.append(f"T:{normalized_ports}")
            else:
                args.extend(["-p", normalized_ports])
        elif port_mode == "top_1000":
            if udp_enabled:
                port_specs.append(f"T:1-1024,{common_tcp}")
            else:
                args.extend(["--top-ports", "1000"])
        elif port_mode == "all_ports":
            if udp_enabled:
                port_specs.append("T:1-65535")
            else:
                args.append("-p-")
        elif port_mode == "service_common":
            if udp_enabled:
                port_specs.append(f"T:{common_tcp}")
            else:
                args.extend(["-p", common_tcp])
        else:
            if udp_enabled:
                port_specs.append(f"T:{common_tcp}")
            else:
                args.extend(["--top-ports", "100"])

        if udp_enabled:
            if udp_mode == "udp_full":
                port_specs.append("U:1-65535")
            elif udp_custom_ports and (udp_mode in ("udp_selected", "udp_custom", "udp_range") or options.get("udp_ports")):
                port_specs.append(f"U:{parse_and_validate_ports(udp_custom_ports)}")
            else:
                port_specs.append("U:53,67,68,69,123,137,138,161,162,500,514,1900,4500")

        if port_specs:
            args.extend(["-p", ",".join(port_specs)])

        exclude_ports = (options.get("exclude_ports") or "").strip()
        if exclude_ports:
            norm_excl = parse_and_validate_ports(exclude_ports)
            args.extend(["--exclude-ports", norm_excl])

        # 4. Service & Script Enumeration (safe flags only)
        if options.get("service_version", True):
            args.append("-sV")
            intensity = options.get("version_intensity")
            if intensity is not None:
                val = max(0, min(9, int(intensity)))
                args.extend(["--version-intensity", str(val)])

        if options.get("default_scripts"):
            args.append("-sC")

        if options.get("banner_grab"):
            args.append("--script=banner")

        if options.get("os_detection"):
            if not has_raw:
                raise ValueError("OS fingerprinting (-O) requires elevated raw-socket privileges on this host.")
            args.append("-O")

        timing = str(options.get("timing", "T3") or "T3").upper()
        if timing in ALLOWED_TIMING_PROFILES:
            args.append(f"-{timing}")

        return args

    def execute_custom_scan(
        self,
        auth_record: TargetAuthorizationRecord,
        options: Dict[str, Any],
        output_dir: Optional[str] = None,
        timeout: Optional[int] = None,
        allow_privileged: bool = False
    ) -> NmapCollectorResult:
        """
        Executes a manually configured active Nmap scan built purely from validated allowlisted flags.
        """
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"Nmap binary not found at: '{self.binary_path}'")

        custom_args = self.build_safe_custom_args(options, allow_privileged=allow_privileged)
        target = auth_record.target
        effective_timeout = timeout or self.timeout

        xml_path = stdout_path = stderr_path = metadata_path = None
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            xml_path = os.path.join(output_dir, "nmap_scan.xml")
            stdout_path = os.path.join(output_dir, "nmap_stdout.txt")
            stderr_path = os.path.join(output_dir, "nmap_stderr.txt")
            metadata_path = os.path.join(output_dir, "scan_metadata.json")

        cmd = [self.binary_path]
        if allow_privileged and shutil.which("sudo"):
            try:
                chk = subprocess.run(["sudo", "-n", self.binary_path, "--version"], capture_output=True, text=True, timeout=2)
                if chk.returncode == 0:
                    cmd = ["sudo", "-n", self.binary_path]
            except Exception:
                pass
        cmd.extend(custom_args)
        if xml_path:
            cmd.extend(["-oX", xml_path])
        cmd.append(target)

        return self._run_command_with_evidence(
            cmd=cmd,
            effective_timeout=effective_timeout,
            output_dir=output_dir,
            xml_path=xml_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            metadata_path=metadata_path
        )

    def _run_command_with_evidence(
        self,
        cmd: List[str],
        effective_timeout: int,
        output_dir: Optional[str],
        xml_path: Optional[str],
        stdout_path: Optional[str],
        stderr_path: Optional[str],
        metadata_path: Optional[str]
    ) -> NmapCollectorResult:
        start_time = datetime.now(timezone.utc)
        returncode = -1
        stdout = ""
        stderr = ""
        error_message = None

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=effective_timeout
            )
            returncode = proc.returncode
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            if returncode != 0:
                error_message = f"Nmap exited with non-zero code {returncode}: {stderr.strip() or stdout.strip()}"
        except subprocess.TimeoutExpired:
            returncode = -1
            error_message = f"Nmap execution timed out after {effective_timeout} seconds"
            stderr = error_message
        except Exception as e:
            returncode = -2
            error_message = f"Nmap execution failed: {str(e)}"
            stderr = error_message

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        file_hashes: Dict[str, str] = {}
        if output_dir:
            if stdout_path:
                try:
                    with open(stdout_path, "w", encoding="utf-8") as f:
                        f.write(stdout)
                    file_hashes["stdout"] = compute_file_sha256(stdout_path)
                except IOError as ioe:
                    stderr += f"\nFailed to write stdout file: {ioe}"
            if stderr_path:
                try:
                    with open(stderr_path, "w", encoding="utf-8") as f:
                        f.write(stderr)
                    file_hashes["stderr"] = compute_file_sha256(stderr_path)
                except IOError:
                    pass
            if xml_path and os.path.exists(xml_path):
                file_hashes["xml"] = compute_file_sha256(xml_path)

        return NmapCollectorResult(
            command_list=cmd,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            xml_path=xml_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            metadata_path=metadata_path,
            duration_seconds=duration,
            file_hashes=file_hashes,
            error_message=error_message
        )

    def _detect_version(self) -> str:
        """Dynamically detects installed Nmap version via subprocess."""
        if os.path.exists(self.binary_path):
            try:
                proc = subprocess.run(
                    [self.binary_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = proc.stdout or proc.stderr or ""
                match = re.search(r"Nmap\s+version\s+([\d\.]+)", output, re.IGNORECASE)
                if match:
                    return match.group(1)
            except Exception:
                pass
        return "7.99"

    def execute_scan(
        self,
        auth_record: TargetAuthorizationRecord,
        profile_name: str = "lab-basic",
        output_dir: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> NmapCollectorResult:
        """
        Executes Nmap scan using safe argument lists and preserves raw XML and logs.
        """
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"Nmap binary not found at: '{self.binary_path}'")

        if profile_name not in SUPPORTED_PROFILES:
            raise ValueError(
                f"Unsupported scan profile '{profile_name}'. "
                f"Supported profiles: {list(SUPPORTED_PROFILES.keys())}"
            )

        target = auth_record.target
        effective_timeout = timeout or self.timeout

        # Output paths
        xml_path = None
        stdout_path = None
        stderr_path = None
        metadata_path = None

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            xml_path = os.path.join(output_dir, "nmap_scan.xml")
            stdout_path = os.path.join(output_dir, "nmap_stdout.txt")
            stderr_path = os.path.join(output_dir, "nmap_stderr.txt")
            metadata_path = os.path.join(output_dir, "scan_metadata.json")

        profile_args = SUPPORTED_PROFILES[profile_name]["args"]

        # Build argument list strictly without shell=True
        cmd = [self.binary_path] + list(profile_args)
        if xml_path:
            cmd.extend(["-oX", xml_path])
        cmd.append(target)

        start_time = datetime.now(timezone.utc)
        returncode = -1
        stdout = ""
        stderr = ""
        error_message = None

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=effective_timeout
            )
            returncode = proc.returncode
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""

            if returncode != 0:
                error_message = f"Nmap exited with non-zero code {returncode}: {stderr.strip() or stdout.strip()}"
        except subprocess.TimeoutExpired:
            returncode = -1
            error_message = f"Nmap execution timed out after {effective_timeout} seconds"
            stderr = error_message
        except Exception as e:
            returncode = -2
            error_message = f"Nmap execution failed: {str(e)}"
            stderr = error_message

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        # Save standard streams if output directory was configured
        file_hashes: Dict[str, str] = {}
        if output_dir:
            if stdout_path:
                try:
                    with open(stdout_path, "w", encoding="utf-8") as f:
                        f.write(stdout)
                    file_hashes["stdout"] = compute_file_sha256(stdout_path)
                except IOError as ioe:
                    stderr += f"\nFailed to write stdout file: {ioe}"

            if stderr_path:
                try:
                    with open(stderr_path, "w", encoding="utf-8") as f:
                        f.write(stderr)
                    file_hashes["stderr"] = compute_file_sha256(stderr_path)
                except IOError as ioe:
                    pass

            if xml_path and os.path.exists(xml_path):
                file_hashes["xml"] = compute_file_sha256(xml_path)

        return NmapCollectorResult(
            command_list=cmd,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            xml_path=xml_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            metadata_path=metadata_path,
            duration_seconds=duration,
            file_hashes=file_hashes,
            error_message=error_message
        )

