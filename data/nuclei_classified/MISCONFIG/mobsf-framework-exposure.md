# Vulnerability: MobSF Framework - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`mobsf-framework-exposure.yaml`)

## Description
MobSF Framework is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/recent_scans/
```

