# Vulnerability: Oracle Business Intelligence Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`oracle-business-intelligence.yaml`)

## Description
Oracle Business Intelligence login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/saw.dll?bieehome&startPage=1
GET {{BaseURL}}/analytics/saw.dll?bieehome&startPage=1
GET {{BaseURL}}/analytics/saw.dll?Dashboard
```

