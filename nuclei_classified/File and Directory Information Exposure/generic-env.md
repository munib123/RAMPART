# Nuclei Template: Generic Env File Disclosure
**Template ID:** generic-env
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** High
**CWE:** CWE-552
**Source:** Nuclei Template (`generic-env.yaml`)

## Vulnerability Information & PoC

## Description
A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

