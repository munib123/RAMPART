# Vulnerability: Zoomitir User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zoomitir.yaml`)

## Description
Zoomitir user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.zoomit.ir/user/{{user}}/
```

