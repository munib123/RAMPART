# Nuclei Template: Teampass LDAP Debug Config - Detect
**Template ID:** teampass-ldap
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`teampass-ldap.yaml`)

## Vulnerability Information & PoC

## Description
Teampass ldap.debug.txt config was detected. This file is generated on "/files/ldap.debug.txt" for versions earlier than 3.0.0.0 when utilizing the "Test current configuration" in LDAP settings.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/files/ldap.debug.txt
```

## References
- https://github.com/nilsteampassnet/TeamPass/commit/ea9838481a58879cdf3def31046955efcff5a546#diff-61809be6a8fff101e3748a0c7dfad90bR16
