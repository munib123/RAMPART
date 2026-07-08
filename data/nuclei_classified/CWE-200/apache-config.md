# Vulnerability: Apache Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apache-config.yaml`)

## Description
Apache configuration file was detected.

## Secure Mitigation
Remove the configuration file from the web root.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/apache.conf
```

