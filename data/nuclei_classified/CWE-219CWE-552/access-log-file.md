# Vulnerability: Publicly accessible access-log file
**Classification:** CWE-219,CWE-552
**Source:** Nuclei Template (`access-log-file.yaml`)

## Description
Log file was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/access.log
GET {{BaseURL}}/log/access.log
GET {{BaseURL}}/logs/access.log
GET {{BaseURL}}/application/logs/access.log
```

