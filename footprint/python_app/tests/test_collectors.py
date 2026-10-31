"""Unit tests for passive reconnaissance collectors using controlled mock fixtures."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx
import dns.resolver
import dns.exception

from app.services.collectors.rdap import RDAPCollector
from app.services.collectors.dns_collector import DNSCollector
from app.services.collectors.crtsh import CertificateTransparencyCollector
from app.services.collectors.theharvester import TheHarvesterCollector
from app.services.collectors.search_collector import PublicSearchCollector


@pytest.mark.asyncio
async def test_rdap_collector_successful_response():
    mock_rdap_json = {
        "ldhName": "example.com",
        "status": ["active", "clientTransferProhibited"],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar LLC"]]],
                "handle": "REG-123",
            }
        ],
        "nameservers": [
            {"ldhName": "ns1.example.com"},
            {"ldhName": "ns2.example.com"},
        ],
    }

    collector = RDAPCollector(bootstrap_url="https://rdap.example.org")

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_rdap_json
        mock_resp.url = "https://rdap.example.org/domain/example.com"
        mock_get.return_value = mock_resp

        result = await collector.collect("example.com")

        assert result.status == "SUCCESS"
        assert result.source_type == "RDAP"
        types = [f.entity_type for f in result.findings]
        assert "DOMAIN" in types
        assert "ORGANIZATION" in types
        assert "HOST" in types
        values = [f.raw_value for f in result.findings]
        assert "example.com" in values
        assert "Example Registrar LLC" in values
        assert "ns1.example.com" in values


@pytest.mark.asyncio
async def test_rdap_collector_fallback_whois():
    collector = RDAPCollector(bootstrap_url="https://rdap.example.org")

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.url = "https://rdap.example.org/domain/fallback.org"
        mock_get.return_value = mock_resp

        fake_whois = (
            "Domain Name: fallback.org\n"
            "Registrar: Public Interest Registry\n"
            "Name Server: ns1.fallback.org\n"
            "Name Server: ns2.fallback.org\n"
        )

        with patch("app.services.collectors.rdap.query_whois_with_fallback") as mock_whois:
            mock_whois.return_value = (True, fake_whois, "whois.pir.org")

            result = await collector.collect("fallback.org")

            assert result.status == "SUCCESS"
            assert result.source_type == "WHOIS"
            assert result.source_name == "whois.pir.org"
            types = [f.entity_type for f in result.findings]
            assert "DOMAIN" in types
            assert "ORGANIZATION" in types
            assert "HOST" in types


@pytest.mark.asyncio
async def test_dns_collector_successful_records():
    collector = DNSCollector(timeout_seconds=2)

    def mock_resolve_impl(target, rtype):
        mock_rrset = MagicMock()
        mock_rrset.ttl = 300
        if rtype == "A":
            r1 = MagicMock()
            r1.to_text.return_value = "93.184.216.34"
            return MagicMock(rrset=mock_rrset, __iter__=lambda self: iter([r1]))
        elif rtype == "MX":
            r1 = MagicMock()
            r1.to_text.return_value = "10 mail.example.com."
            return MagicMock(rrset=mock_rrset, __iter__=lambda self: iter([r1]))
        elif rtype == "TXT":
            r1 = MagicMock()
            r1.to_text.return_value = '"v=spf1 -all"'
            return MagicMock(rrset=mock_rrset, __iter__=lambda self: iter([r1]))
        else:
            raise dns.resolver.NoAnswer

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=mock_resolve_impl):
        result = await collector.collect("example.com")

        assert result.status in ("SUCCESS", "PARTIAL")
        assert result.source_type == "DNS"
        types = [f.entity_type for f in result.findings]
        assert "IP_ADDRESS" in types
        assert "HOST" in types
        assert "DNS_RECORD" in types
        values = [f.raw_value for f in result.findings]
        assert "93.184.216.34" in values
        assert "mail.example.com" in values


@pytest.mark.asyncio
async def test_dns_collector_nxdomain_handling():
    collector = DNSCollector(timeout_seconds=2)

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
        result = await collector.collect("nonexistent-test-domain.org")

        assert result.status == "SUCCESS"
        assert result.raw_content["status_by_type"]["A"] == "NXDOMAIN"


@pytest.mark.asyncio
async def test_crtsh_collector_successful():
    collector = CertificateTransparencyCollector(base_url="https://crt.sh")

    mock_crt_list = [
        {
            "id": 1234567,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "example.com",
            "name_value": "example.com\napi.example.com\nadmin.example.com",
            "entry_timestamp": "2026-01-01T00:00:00",
        }
    ]

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_crt_list
        mock_resp.url = "https://crt.sh/?q=%.example.com&output=json"
        mock_get.return_value = mock_resp

        result = await collector.collect("example.com")

        assert result.status == "SUCCESS"
        assert result.source_type == "CERTIFICATE_TRANSPARENCY"
        types = [f.entity_type for f in result.findings]
        assert "CERTIFICATE" in types
        assert "SUBDOMAIN" in types
        values = [f.raw_value for f in result.findings]
        assert "api.example.com" in values
        assert "admin.example.com" in values


@pytest.mark.asyncio
async def test_crtsh_collector_unconfigured():
    collector = CertificateTransparencyCollector(base_url="")
    result = await collector.collect("example.com")
    assert result.status == "NOT_CONFIGURED"


@pytest.mark.asyncio
async def test_theharvester_missing_executable():
    collector = TheHarvesterCollector(binary_path="nonexistent_theharvester_binary_xyz")
    result = await collector.collect("example.com")
    assert result.status == "NOT_CONFIGURED"
    assert result.error_category == "MISSING_EXECUTABLE"


@pytest.mark.asyncio
async def test_theharvester_mocked_execution():
    collector = TheHarvesterCollector(binary_path="theHarvester")

    with patch.object(collector, "is_available", return_value=True):
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        fake_stdout = b"[*] Hosts found: 2\nadmin.example.com\nportal.example.com\n[*] Emails found: 1\nsecurity@example.com\n"
        mock_proc.communicate.return_value = (fake_stdout, b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await collector.collect("example.com")

            assert result.status == "SUCCESS"
            types = [f.entity_type for f in result.findings]
            assert "EMAIL" in types
            assert "SUBDOMAIN" in types
            values = [f.raw_value for f in result.findings]
            assert "security@example.com" in values
            assert "admin.example.com" in values


@pytest.mark.asyncio
async def test_public_search_collector_unconfigured():
    collector = PublicSearchCollector(api_key=None)
    result = await collector.collect("example.com")
    assert result.status == "NOT_CONFIGURED"
