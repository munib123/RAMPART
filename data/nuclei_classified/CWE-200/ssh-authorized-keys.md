# Vulnerability: SSH Authorized Keys File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ssh-authorized-keys.yaml`)

## Description
SSH authorized keys file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.ssh/authorized_keys
GET {{BaseURL}}/_/.ssh/authorized_keys
GET {{BaseURL}}/authorized_keys
GET {{BaseURL}}/.authorized_keys
```

