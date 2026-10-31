"""Unit tests for Nmap detector and tool availability checks."""

import subprocess
from unittest.mock import patch, MagicMock
from app.services.active.nmap_detector import NmapDetector


def test_nmap_detector_installed():
    """Verify detector extracts version and sets READY diagnostic code when Nmap is callable."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Nmap version 7.98 ( https://nmap.org )\nPlatform: i686-pc-windows-windows"
    mock_proc.stderr = ""

    detector = NmapDetector(binary_override="/usr/bin/nmap")
    with patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("subprocess.run", return_value=mock_proc):
        
        status = detector.check_availability()
        assert status["is_available"] is True
        assert status["version"] == "7.98"
        assert status["diagnostic_code"] == "READY"
        assert "tcp_connect_scan" in status["capabilities"]
        assert status["error"] is None


def test_nmap_detector_missing_binary():
    """Verify detector reports NOT_INSTALLED when no binary is found."""
    detector = NmapDetector(binary_override="/nonexistent/nmap")
    with patch("os.path.isfile", return_value=False), \
         patch("shutil.which", return_value=None):
        
        status = detector.check_availability()
        assert status["is_available"] is False
        assert status["version"] is None
        assert status["diagnostic_code"] == "NOT_INSTALLED"
        assert status["capabilities"] == []


def test_nmap_detector_nonzero_exit():
    """Verify detector handles non-zero exit code gracefully."""
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""
    mock_proc.stderr = "Fatal error: unexpected environment condition"

    detector = NmapDetector(binary_override="/usr/bin/nmap")
    with patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("subprocess.run", return_value=mock_proc):
        
        status = detector.check_availability()
        assert status["is_available"] is False
        assert status["diagnostic_code"] == "INVOCATION_FAILED"
        assert "Fatal error" in status["error"]


def test_nmap_detector_permission_denied():
    """Verify detector handles PermissionError without crashing."""
    detector = NmapDetector(binary_override="/usr/bin/nmap")
    with patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("subprocess.run", side_effect=PermissionError("Access denied")):
        
        status = detector.check_availability()
        assert status["is_available"] is False
        assert status["diagnostic_code"] == "PERMISSION_DENIED"
        assert "Access denied" in status["error"]


def test_nmap_detector_timeout():
    """Verify detector handles timeout without crashing."""
    detector = NmapDetector(binary_override="/usr/bin/nmap")
    with patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["nmap", "--version"], timeout=5)):
        
        status = detector.check_availability()
        assert status["is_available"] is False
        assert status["diagnostic_code"] == "TIMEOUT"
