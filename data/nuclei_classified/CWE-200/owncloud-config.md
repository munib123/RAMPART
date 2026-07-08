# Vulnerability: owncloud Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`owncloud-config.yaml`)

## Description
owncloud configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/owncloud/config/
```

