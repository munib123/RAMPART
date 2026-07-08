# Vulnerability: Unauthenticated ZyXEL USG ZTP - Detect
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauth-ztp-ping.yaml`)

## Description
Make a ZyXEL USG with ZTP support, pre CVE-2023-28771 patch, do a DNS lookup by asking it to make an ICMP request.
This template can be used to detect hosts potentially vulnerable to CVE-2023-28771, CVE-2022-30525, and other issues, without actually exploiting the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ztp/cgi-bin/handler HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"command":"ping","dest":"{{interactsh-url}}"}
```

