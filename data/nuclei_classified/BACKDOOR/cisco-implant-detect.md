# Vulnerability: Cisco IOS XE - Impant Detection
**Classification:** BACKDOOR
**Source:** Nuclei Template (`cisco-implant-detect.yaml`)

## Description
Cisco is aware of active exploitation of a previously unknown vulnerability in the web UI feature of Cisco IOS XE Software when exposed to the internet or to untrusted networks. This vulnerability allows a remote, unauthenticated attacker to create an account on an affected system with privilege level 15 access. The attacker can then use that account to gain control of the affected system.

## Secure Mitigation
Disable the HTTP server feature on internet-facing systems by running one of the following commands in global configuration mode: 'no ip http server' or 'no ip http secure-server'.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /webui HTTP/1.1
Host: {{Hostname}}

POST /webui/logoutconfirm.html?logon_hash=1 HTTP/1.1
Host: {{Hostname}}
Authorization: 0ff4fbf0ecffa77ce8d3852a29263e263838e9bb
```

