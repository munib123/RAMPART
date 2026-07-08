# Vulnerability: Tekton Dashboard Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tekton-dashboard.yaml`)

## Description
Tekton Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/pipelines
```

