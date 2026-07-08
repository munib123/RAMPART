# Vulnerability: Teampass LDAP Debug Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`teampass-ldap.yaml`)

## Description
Teampass ldap.debug.txt config was detected. This file is generated on "/files/ldap.debug.txt" for versions earlier than 3.0.0.0 when utilizing the "Test current configuration" in LDAP settings.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/files/ldap.debug.txt
```

