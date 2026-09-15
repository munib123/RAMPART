# Nuclei Template: Apache NiFi - Unauthenticated Access
**Template ID:** apache-nifi-unauth
**Vulnerability Class:** Improper Authorization
**Severity:** High
**CWE:** CWE-285
**Source:** Nuclei Template (`apache-nifi-unauth.yaml`)

## Vulnerability Information & PoC

## Description
Apache NiFi server was able to be accessed because no authentication was required.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/nifi-api/access/config
```

## References
- https://github.com/jm0x0/apache_nifi_processor_rce
