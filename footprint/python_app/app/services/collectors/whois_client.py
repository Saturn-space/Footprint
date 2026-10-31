"""RFC 3912 TCP WHOIS client with referral resolution and timeout enforcement."""

import socket
import re
from typing import Optional, Tuple


def query_whois_server(server: str, query: str, timeout: int = 10, port: int = 43) -> str:
    """Sends a raw WHOIS query over TCP socket (RFC 3912) and reads response."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.sendall(f"{query}\r\n".encode("utf-8"))

        response_chunks = []
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response_chunks.append(data)
            except socket.timeout:
                break

    raw_text = b"".join(response_chunks).decode("utf-8", errors="replace")
    return raw_text


def query_whois_with_fallback(domain: str, timeout: int = 10) -> Tuple[bool, str, str]:
    """Queries standard WHOIS starting at whois.iana.org with single referral traversal.

    Returns:
        (success, whois_text, server_queried)
    """
    clean_domain = domain.strip().lower()

    # Determine TLD
    parts = clean_domain.split(".")
    if len(parts) < 2:
        return False, "Invalid domain for WHOIS lookup", "none"

    tld = parts[-1]
    # Standard common server mapping
    server_map = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "ai": "whois.nic.ai",
        "co": "whois.nic.co",
        "uk": "whois.nic.uk",
        "ca": "whois.cira.ca",
        "de": "whois.denic.de",
        "in": "whois.registry.in",
    }

    server = server_map.get(tld, "whois.iana.org")

    try:
        raw_res = query_whois_server(server, clean_domain, timeout=timeout)
        # If IANA was queried and returned a referral whois server, query the referral
        if server == "whois.iana.org":
            referral_match = re.search(r"whois:\s*([a-zA-Z0-9\.\-]+)", raw_res, re.IGNORECASE)
            if referral_match:
                referral_server = referral_match.group(1).strip()
                referral_res = query_whois_server(referral_server, clean_domain, timeout=timeout)
                return True, referral_res, referral_server

        return True, raw_res, server
    except Exception as exc:
        return False, f"WHOIS query failed: {exc}", server
