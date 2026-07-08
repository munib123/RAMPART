# Vulnerability: Drone CI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`drone-ci-panel.yaml`)

## Description
Drone CI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/welcome
```

