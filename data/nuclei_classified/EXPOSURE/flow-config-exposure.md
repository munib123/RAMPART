# Vulnerability: Flow Configuration - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`flow-config-exposure.yaml`)

## Description
Detects an exposed Flow configuration file. These files may contain sensitive information such as credentials, internal endpoints, or environment settings.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.flowconfig
```

