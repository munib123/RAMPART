# Vulnerability: Ansible AWX Detection
**Classification:** TECH
**Source:** Nuclei Template (`ansible-awx-detect.yaml`)

## Description
Detects Ansible AWX Instance

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/
```

