# Nuclei Template: SVN Configuration - Detect
**Template ID:** exposed-svn
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`exposed-svn.yaml`)

## Vulnerability Information & PoC

## Description
SVN configuration was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.svn/entries
```

