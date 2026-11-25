"""
OSINT-RECON Master Environment Verification Suite
Validates all 15 core environmental, toolchain, and structural requirements.
"""

import os
import sys
import json
import shutil
import subprocess

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)


def test_1_os_detection():
    print("[TEST 1] OS Detection...")
    with open("/etc/os-release", "r") as f:
        content = f.read()
    assert "Kali" in content or "kali" in content, "Operating system is not Kali Linux"
    print("  -> Passed: Kali Linux identified")


def test_2_storage_recognition():
    print("[TEST 2] Storage Recognition...")
    stat = os.statvfs("/")
    free_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
    total_gb = (stat.f_blocks * stat.f_frsize) / (1024 ** 3)
    print(f"  -> Total: {total_gb:.1f} GB | Free: {free_gb:.1f} GB")
    assert free_gb >= 20.0, f"Insufficient free disk space: {free_gb:.1f} GB < 20 GB"
    print("  -> Passed: Storage capacity exceeds 20 GB threshold")


def test_3_network_connectivity():
    print("[TEST 3] Network Connectivity...")
    res = subprocess.run(["ping", "-c", "2", "-W", "3", "8.8.8.8"], capture_output=True, text=True)
    assert res.returncode == 0, f"Ping to 8.8.8.8 failed: {res.stderr}"
    print("  -> Passed: Outbound IPv4 Internet connectivity verified")


def test_4_dns_resolution():
    print("[TEST 4] DNS Resolution...")
    import dns.resolver
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    answers = resolver.resolve("google.com", "A")
    assert len(answers) > 0, "No A records returned for google.com"
    print(f"  -> Passed: DNS resolved google.com to {answers[0]}")


def test_5_python_environment():
    print("[TEST 5] Python Environment...")
    assert sys.version_info >= (3, 10), f"Python version too old: {sys.version}"
    assert ".venv" in sys.executable, f"Interpreter is not running inside virtualenv: {sys.executable}"
    print(f"  -> Passed: Isolated interpreter active ({sys.executable})")


def test_6_python_dependencies():
    print("[TEST 6] Python Dependencies...")
    import dns.resolver
    import whois
    import nmap
    import requests
    import bs4
    import lxml
    import reportlab
    import pydantic
    import dotenv
    print("  -> Passed: All 9 core dependencies imported successfully")


def test_7_whois_availability():
    print("[TEST 7] WHOIS Availability...")
    whois_bin = shutil.which("whois")
    assert whois_bin is not None, "whois executable not found in PATH"
    res = subprocess.run([whois_bin, "--version"], capture_output=True, text=True)
    assert res.returncode == 0, "whois --version failed"
    print(f"  -> Passed: WHOIS verified at {whois_bin}")


def test_8_dns_utilities():
    print("[TEST 8] DNS Utilities (dig & nslookup)...")
    dig_bin = shutil.which("dig")
    nslookup_bin = shutil.which("nslookup")
    assert dig_bin is not None, "dig not found in PATH"
    assert nslookup_bin is not None, "nslookup not found in PATH"
    print(f"  -> Passed: dig ({dig_bin}) and nslookup ({nslookup_bin}) verified")


def test_9_nmap_availability():
    print("[TEST 9] Nmap Availability...")
    nmap_bin = shutil.which("nmap")
    assert nmap_bin is not None, "nmap executable not found in PATH"
    res = subprocess.run([nmap_bin, "--version"], capture_output=True, text=True)
    assert "Nmap version" in res.stdout, "Unexpected nmap output"
    print(f"  -> Passed: Nmap verified at {nmap_bin}")


def test_10_nmap_python_integration():
    print("[TEST 10] Nmap Python Integration...")
    import nmap
    nm = nmap.PortScanner()
    ver = nm.nmap_version()
    assert ver[0] >= 7, f"Unexpected nmap version: {ver}"
    print(f"  -> Passed: python-nmap connected to Nmap version {ver}")


def test_11_theharvester_availability():
    print("[TEST 11] theHarvester Availability...")
    harv_bin = shutil.which("theHarvester")
    assert harv_bin is not None, "theHarvester executable not found in PATH"
    res = subprocess.run([harv_bin, "-h"], capture_output=True, text=True)
    assert "theHarvester" in res.stdout or "theHarvester" in res.stderr, "theHarvester failed to respond"
    print(f"  -> Passed: theHarvester verified at {harv_bin}")


def test_12_ssh_service():
    print("[TEST 12] SSH Service Status...")
    res = subprocess.run(["systemctl", "is-active", "ssh"], capture_output=True, text=True)
    assert res.stdout.strip() == "active", f"SSH service is not active: {res.stdout.strip()}"
    print("  -> Passed: OpenSSH server is active and running")


def test_13_project_directory_integrity():
    print("[TEST 13] Project Directory Integrity...")
    required_dirs = [
        "config",
        "data/raw_outputs",
        "data/processed",
        "docs",
        "reports",
        "scans/baseline",
        "src",
        "tests",
        ".venv"
    ]
    for d in required_dirs:
        path = os.path.join(PROJECT_ROOT, d)
        assert os.path.isdir(path), f"Missing required directory: {d}"
        
    required_files = [
        "README.md",
        "requirements.txt",
        ".gitignore",
        ".env.example",
        "config/config.example.json",
        "config/recon_schema.json",
        "src/schema.py"
    ]
    for f in required_files:
        path = os.path.join(PROJECT_ROOT, f)
        assert os.path.isfile(path), f"Missing required file: {f}"
    print("  -> Passed: All 9 directories and 7 required files verified")


def test_14_json_schema_validity():
    print("[TEST 14] JSON Schema & Pydantic Validity...")
    from src.schema import ReconRecord, TargetInfo, ToolInfo
    schema_path = os.path.join(PROJECT_ROOT, "config", "recon_schema.json")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_dict = json.load(f)
    assert "$schema" in schema_dict, "Missing $schema declaration"
    assert "properties" in schema_dict, "Missing properties in schema"
    
    # Test instantiating model
    rec = ReconRecord(
        target_info=TargetInfo(
            target="127.0.0.1",
            category="local_loopback",
            authorization_status="AUTHORIZED_LOCAL_LAB",
            scope="127.0.0.1"
        ),
        tool_info=ToolInfo(name="test", version="1.0"),
        recon_category="port_scan",
        evidence_source="unit-test"
    )
    dumped = json.loads(rec.model_dump_json())
    assert dumped["target_info"]["target"] == "127.0.0.1"
    print("  -> Passed: JSON schema file and Pydantic validation functional")


def test_15_git_configuration():
    print("[TEST 15] Git Configuration...")
    git_bin = shutil.which("git")
    assert git_bin is not None, "git not found in PATH"
    assert os.path.isdir(os.path.join(PROJECT_ROOT, ".git")), ".git directory missing"
    
    # Verify .gitignore content
    gitignore_path = os.path.join(PROJECT_ROOT, ".gitignore")
    with open(gitignore_path, "r") as f:
        gi = f.read()
    assert ".venv/" in gi, ".venv not in .gitignore"
    assert ".env" in gi, ".env not in .gitignore"
    print("  -> Passed: Git repository initialized with proper .gitignore exclusions")


if __name__ == "__main__":
    print("=================================================================")
    print("  OSINT-RECON AUTOMATED ENVIRONMENT VERIFICATION SUITE")
    print("=================================================================\n")
    tests = [
        test_1_os_detection,
        test_2_storage_recognition,
        test_3_network_connectivity,
        test_4_dns_resolution,
        test_5_python_environment,
        test_6_python_dependencies,
        test_7_whois_availability,
        test_8_dns_utilities,
        test_9_nmap_availability,
        test_10_nmap_python_integration,
        test_11_theharvester_availability,
        test_12_ssh_service,
        test_13_project_directory_integrity,
        test_14_json_schema_validity,
        test_15_git_configuration
    ]
    
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  [!] FAILED: {e}")
            failed += 1
            
    print(f"\n=================================================================")
    print(f"  VERIFICATION RESULTS: {passed} PASSED | {failed} FAILED")
    print("=================================================================")
    if failed > 0:
        sys.exit(1)
    else:
        print("  ALL 15 VERIFICATION SUITES COMPLETED SUCCESSFULLY!")
        sys.exit(0)

