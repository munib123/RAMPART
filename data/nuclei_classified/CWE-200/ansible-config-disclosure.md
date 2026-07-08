# Vulnerability: Ansible Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ansible-config-disclosure.yaml`)

## Description
Ansible configuration page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ansible.cfg
```

