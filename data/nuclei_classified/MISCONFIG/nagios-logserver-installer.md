# Vulnerability: Nagios Log Server - Install
**Classification:** MISCONFIG
**Source:** Nuclei Template (`nagios-logserver-installer.yaml`)

## Description
Detects the presence of a Nagios Log Server installation page, which can expose configuration setup information or initialization steps.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nagioslogserver/install
```

