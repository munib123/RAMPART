# Vulnerability: Alibaba Canal Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`alibaba-canal-info-leak.yaml`)

## Description
Alibaba Canal configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/canal/config/1/1
```

