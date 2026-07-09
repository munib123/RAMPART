# Nuclei Template: Ansible Configuration Page - Detect
**Template ID:** ansible-config-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`ansible-config-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Ansible configuration page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ansible.cfg
```

