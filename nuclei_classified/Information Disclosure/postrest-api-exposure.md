# Nuclei Template: PostgREST API Server  - Exposure
**Template ID:** postrest-api-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`postrest-api-exposure.yaml`)

## Vulnerability Information & PoC

## Description
PostgREST API Server was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

