# Vulnerability: SSH Known Hosts File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ssh-known-hosts.yaml`)

## Description
SSH known hosts file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.ssh/known_hosts
GET {{BaseURL}}/.ssh/known_hosts.old
```

