# Nuclei Template: MemTracker - Exposure
**Template ID:** memtracker-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`memtracker-exposure.yaml`)

## Vulnerability Information & PoC

## Description
MemTracker was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/mem_tracker
```

