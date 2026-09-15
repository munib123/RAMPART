# Nuclei Template: CRXDE Lite - Exposure
**Template ID:** crxde-lite
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`crxde-lite.yaml`)

## Vulnerability Information & PoC

## Description
CRXDE Lite exposure was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/crx/de/index.jsp
```

## References
- https://github.com/Az0x7/vulnerability-Checklist/blob/main/Aem%20misconfiguration/aem.md
