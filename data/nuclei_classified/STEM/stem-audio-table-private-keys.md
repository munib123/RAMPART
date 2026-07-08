# Vulnerability: Detect Private Key on STEM Audio Table
**Classification:** STEM
**Source:** Nuclei Template (`stem-audio-table-private-keys.yaml`)

## Description
Private Key on STEM audio table was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/privatekey.pem
```

