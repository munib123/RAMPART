# Vulnerability: Monitorix Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`monitorix-exposure.yaml`)

## Description
Monitorix panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/monitorix-cgi/monitorix.cgi?mode=localhost&graph=all&when=1day
```

