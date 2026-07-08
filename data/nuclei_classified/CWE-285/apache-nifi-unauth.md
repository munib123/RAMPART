# Vulnerability: Apache NiFi - Unauthenticated Access
**Classification:** CWE-285
**Source:** Nuclei Template (`apache-nifi-unauth.yaml`)

## Description
Apache NiFi server was able to be accessed because no authentication was required.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nifi-api/access/config
```

