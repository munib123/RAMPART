# Vulnerability: Windows Remote Management - Detection
**Classification:** NETWORK
**Source:** Nuclei Template (`winrm-detect.yaml`)

## Description
Detects Windows Remote Management (WinRM) by checking HTTP response headers on ports 5985 (HTTP) and 5986 (HTTPS).

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/wsman
```

