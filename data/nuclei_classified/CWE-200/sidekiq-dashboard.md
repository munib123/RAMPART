# Vulnerability: Sidekiq Dashboard Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sidekiq-dashboard.yaml`)

## Description
Sidekiq Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sidekiq
```

