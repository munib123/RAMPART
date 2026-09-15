# Nuclei Template: HG Configuration - Detect
**Template ID:** exposed-hg
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`exposed-hg.yaml`)

## Vulnerability Information & PoC

## Description
HG configuration was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.hg/hgrc
```

