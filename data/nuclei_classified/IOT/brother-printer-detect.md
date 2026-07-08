# Vulnerability: Brother Printer
**Classification:** IOT
**Source:** Nuclei Template (`brother-printer-detect.yaml`)

## Description
Brother Printer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/general/status.html
```

