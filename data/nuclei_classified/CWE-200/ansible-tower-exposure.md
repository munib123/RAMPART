# Vulnerability: Ansible Tower - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ansible-tower-exposure.yaml`)

## Description
Ansible Tower was detected. Ansible Tower is a commercial offering that helps teams manage complex multi-tier deployments by adding control, knowledge, and delegation to Ansible-powered environments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

