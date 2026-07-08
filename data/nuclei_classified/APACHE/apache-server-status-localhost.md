# Vulnerability: Server Status Disclosure
**Classification:** APACHE
**Source:** Nuclei Template (`apache-server-status-localhost.yaml`)

## Description
Apache Server Status page is exposed, which may contain information about pages visited by the users, their IPs or sensitive information such as session tokens.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/server-status
GET {{BaseURL}}/server-status
```

