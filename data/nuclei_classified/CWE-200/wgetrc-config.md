# Vulnerability: Wgetrc Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wgetrc-config.yaml`)

## Description
Wgetrc configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wgetrc
GET {{BaseURL}}/.wgetrc
```

