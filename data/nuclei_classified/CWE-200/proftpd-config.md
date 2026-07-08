# Vulnerability: ProFTPD Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`proftpd-config.yaml`)

## Description
ProFTPD configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/proftpd.conf
```

