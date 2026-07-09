# Nuclei Template: AppVeyor Configuration Page - Detect
**Template ID:** appveyor-configuration-file
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`appveyor-configuration-file.yaml`)

## Vulnerability Information & PoC

## Description
AppVeyor configuration page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.appveyor.yml
GET {{BaseURL}}/appveyor.yml
```

