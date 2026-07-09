# Nuclei Template: PHPinfo Page - Detect
**Template ID:** phpinfo-files
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`phpinfo-files.yaml`)

## Vulnerability Information & PoC

## Description
PHPinfo page was detected. The output of the phpinfo() command can reveal sensitive and detailed PHP environment information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

## Remediation
Remove PHP Info pages from publicly accessible sites, or restrict access to authorized users only.

