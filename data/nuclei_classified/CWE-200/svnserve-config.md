# Vulnerability: Svnserve Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`svnserve-config.yaml`)

## Description
Svnserve configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/svnserve.conf
```

