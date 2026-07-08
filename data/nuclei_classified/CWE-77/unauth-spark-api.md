# Vulnerability: Unauthenticated Spark REST API
**Classification:** CWE-77
**Source:** Nuclei Template (`unauth-spark-api.yaml`)

## Description
The Spark product's REST API interface allows access to unauthenticated users.

## Secure Mitigation
Restrict access the exposed API ports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v1/submissions
```

