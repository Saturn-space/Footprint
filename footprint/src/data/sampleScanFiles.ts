/**
 * Realistic and safe sample scan outputs for NorthStar Analytics Lab
 * Target: 192.168.56.102 (private host)
 */

export const SAMPLE_NMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -p 22,80,443,5432,8080 -oX nmap_out.xml 192.168.56.102" start="1700000000" version="7.94" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="5" services="22,80,443,5432,8080"/>
  <verbose level="0"/>
  <debugging level="0"/>
  <host starttime="1700000005" endtime="1700000030">
    <status state="up" reason="arp-response"/>
    <address addr="192.168.56.102" addrtype="ipv4"/>
    <hostnames>
      <hostname name="lab-dev-node01.lab.example" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.6" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" extrainfo="Ubuntu" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="ssl/http" product="nginx" version="1.18.0" extrainfo="Ubuntu" tunnel="ssl" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="5432">
        <state state="open" reason="syn-ack"/>
        <service name="postgresql" product="PostgreSQL DB" version="14.9" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Jetty" version="9.4.43.v20210629" extrainfo="Jenkins CI Automation Node" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

export const SAMPLE_OPENVAS_XML = `<?xml version="1.0" encoding="UTF-8"?>
<report id="openvas-rep-847291">
  <report_format id="c1645564-3b62-11e1-839a-406186ea4fc5">XML</report_format>
  <results>
    <result id="res-001">
      <name>Deprecated TLSv1.0 Protocol Enabled</name>
      <host>192.168.56.102</host>
      <port>443/tcp</port>
      <nvt>
        <type>nvt</type>
        <name>SSL/TLS: Deprecated TLSv1.0 Protocol Detection</name>
        <cvss_base>5.0</cvss_base>
        <cve>CVE-2011-3389</cve>
        <solution>Disable TLS 1.0 and TLS 1.1 in web server configuration. Enforce TLS 1.2 or TLS 1.3.</solution>
      </nvt>
      <threat>Medium</threat>
      <severity>5.0</severity>
      <description>The remote service encrypts traffic using the deprecated TLSv1.0 protocol which lacks modern cryptographic cipher suites.</description>
    </result>
    <result id="res-002">
      <name>Jenkins CI Remote Unauthenticated Metrics Exposure</name>
      <host>192.168.56.102</host>
      <port>8080/tcp</port>
      <nvt>
        <type>nvt</type>
        <name>Jenkins Prometheus Metrics Disclosure</name>
        <cvss_base>5.3</cvss_base>
        <cve>CVE-2023-38606</cve>
        <solution>Restrict network access to port 8080 or enable authentication on internal metric scrapers.</solution>
      </nvt>
      <threat>Medium</threat>
      <severity>5.3</severity>
      <description>The Jenkins instance exposes /prometheus metrics endpoint without authentication, revealing internal job names and workspace paths.</description>
    </result>
  </results>
</report>`;
