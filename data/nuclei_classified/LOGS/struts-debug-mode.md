# Vulnerability: Apache Struts setup in Debug-Mode
**Classification:** LOGS
**Source:** Nuclei Template (`struts-debug-mode.yaml`)

## Description
Apache Struts debug mode is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

