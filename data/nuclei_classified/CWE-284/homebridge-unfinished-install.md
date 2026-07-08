# Vulnerability: Homebridge - Unfinished Installation
**Classification:** CWE-284
**Source:** Nuclei Template (`homebridge-unfinished-install.yaml`)

## Description
Homebridge instance with incomplete installation detected. The setup wizard is exposed, allowing anyone to create the first admin account and gain full control over the Homebridge instance. This can lead to unauthorized access to smart home devices and potential network compromise.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/api/auth/settings
```

