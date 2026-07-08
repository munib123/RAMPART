# Vulnerability: Netgear WNR614 - Improper Authentication
**Classification:** CWE-200
**Source:** Nuclei Template (`netgear-wnr614-auth-bypass.yaml`)

## Description
A vulnerability in the Netgear WNR614 router permits unauthorized individuals to bypass the authentication. When adding "%00currentsetting.htm" to the the requested url, it will be recognized as passing the authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/RST_status.htm%00currentsetting.htm
```

