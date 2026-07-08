# Vulnerability: MemTracker - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`memtracker-exposure.yaml`)

## Description
MemTracker was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mem_tracker
```

