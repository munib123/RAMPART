# Vulnerability: IDEMIA BIOMetrics - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`idemia-biometrics-default-login.yaml`)

## Description
IDEMIA BIOMetrics application  default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}

password={{password}}
```

