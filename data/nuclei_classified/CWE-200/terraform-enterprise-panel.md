# Vulnerability: Terraform Enterprise Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`terraform-enterprise-panel.yaml`)

## Description
Terraform Enterprise panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/session
```

