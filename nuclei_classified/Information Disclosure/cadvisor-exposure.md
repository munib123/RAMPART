# Nuclei Template: cAdvisor - Detect
**Template ID:** cadvisor-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`cadvisor-exposure.yaml`)

## Vulnerability Information & PoC

## Description
cAdvisor page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/containers/
```

