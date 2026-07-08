# Vulnerability: 3CX Config - File Disclosure
**Classification:** CWE-219,CWE-552
**Source:** Nuclei Template (`3cx-config.yaml`)

## Description
3CX Configuration file was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SetupConfig.xml
```

