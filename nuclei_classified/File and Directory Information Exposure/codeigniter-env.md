# Nuclei Template: Codeigniter - .env File Discovery
**Template ID:** codeigniter-env
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** High
**CWE:** CWE-552
**Source:** Nuclei Template (`codeigniter-env.yaml`)

## Vulnerability Information & PoC

## Description
Codeigniter .env file was discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

