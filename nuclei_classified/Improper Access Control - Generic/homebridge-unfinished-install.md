# Nuclei Template: Homebridge - Unfinished Installation
**Template ID:** homebridge-unfinished-install
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** High
**CWE:** CWE-284
**Source:** Nuclei Template (`homebridge-unfinished-install.yaml`)

## Vulnerability Information & PoC

## Description
Homebridge instance with incomplete installation detected. The setup wizard is exposed, allowing anyone to create the first admin account and gain full control over the Homebridge instance. This can lead to unauthorized access to smart home devices and potential network compromise.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/api/auth/settings
```

## References
- https://homebridge.io/
- https://github.com/homebridge/homebridge-config-ui-x
