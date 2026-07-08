# Vulnerability: Fuji Xerox Printer Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fuji-xerox-printer-detect.yaml`)

## Description
Fuji Xerox printer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hdstat.htm
```

