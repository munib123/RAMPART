# Vulnerability: RaspberryMatic Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`raspberrymatic-panel.yaml`)

## Description
RaspberryMatic login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.htm
```

