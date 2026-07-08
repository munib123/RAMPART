# Vulnerability: Ansible Semaphore Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ansible-semaphore-panel.yaml`)

## Description
An Ansible Semaphore login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

