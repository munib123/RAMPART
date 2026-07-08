# Vulnerability: Dnsmasq Config - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`dnsmasq-config.yaml`)

## Description
Dnsmasq Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dnsmasq.conf
```

