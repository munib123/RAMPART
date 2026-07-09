# Nuclei Template: SSH Authorized Keys File - Detect
**Template ID:** ssh-authorized-keys
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`ssh-authorized-keys.yaml`)

## Vulnerability Information & PoC

## Description
SSH authorized keys file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.ssh/authorized_keys
GET {{BaseURL}}/_/.ssh/authorized_keys
GET {{BaseURL}}/authorized_keys
GET {{BaseURL}}/.authorized_keys
```

## References
- https://www.ssh.com/academy/ssh/authorized-key
