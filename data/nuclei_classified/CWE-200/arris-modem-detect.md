# Vulnerability: ARRIS Touchstone Telephony Modem - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`arris-modem-detect.yaml`)

## Description
ARRIS Touchstone Telephony Modem status panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phy.htm
```

