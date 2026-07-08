# Vulnerability: Apache Zeppelin - Unauthenticated Access
**Classification:** CWE-285
**Source:** Nuclei Template (`apache-zeppelin-unauth.yaml`)

## Description
Apache Zeppelin server was able to be accessed because no authentication was required.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/security/ticket
```

