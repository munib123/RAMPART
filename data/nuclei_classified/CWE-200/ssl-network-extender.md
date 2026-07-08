# Vulnerability: CheckPoint SSL Network Extender Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ssl-network-extender.yaml`)

## Description
CheckPoint SSL Network Extender login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

