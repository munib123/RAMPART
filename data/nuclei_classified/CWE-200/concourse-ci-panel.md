# Vulnerability: Concourse CI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`concourse-ci-panel.yaml`)

## Description
Concourse CI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

