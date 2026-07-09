# Nuclei Template: FTP Credentials Exposure
**Template ID:** ftp-credentials-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`ftp-credentials-exposure.yaml`)

## Vulnerability Information & PoC

## Description
FTP credentials were detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ftpsync.settings
```

