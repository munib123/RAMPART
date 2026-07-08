# Vulnerability: Stestr Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`stestr-config.yaml`)

## Description
Stestr configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.stestr.conf
```

