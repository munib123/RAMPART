# Nuclei Template: DBeaver - Credentials Discovery
**Template ID:** dbeaver-credentials
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Medium
**CWE:** CWE-522
**Source:** Nuclei Template (`dbeaver-credentials.yaml`)

## Vulnerability Information & PoC

## Description
DBeaver credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /{{str}}.json HTTP/1.1
Host: {{Hostname}}

GET /.dbeaver/credentials-config.json HTTP/1.1
Host: {{Hostname}}
```

