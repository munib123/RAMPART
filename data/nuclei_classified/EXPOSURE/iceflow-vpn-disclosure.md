# Vulnerability: ICEFlow VPN Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`iceflow-vpn-disclosure.yaml`)

## Description
ICEFlow VPN internal log file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/log/system.log
GET {{BaseURL}}/log/vpn.log
GET {{BaseURL}}/log/access.log
GET {{BaseURL}}/log/warn.log
GET {{BaseURL}}/log/error.log
GET {{BaseURL}}/log/debug.log
GET {{BaseURL}}/log/mobile.log
GET {{BaseURL}}/log/firewall.log
```

