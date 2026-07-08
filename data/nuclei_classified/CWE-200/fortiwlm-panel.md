# Vulnerability: Fortinet FortiWLM Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortiwlm-panel.yaml`)

## Description
Fortinet FortiWLM login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wlm/login?next=/wlm
```

