# Vulnerability: UEditor - Arbitrary File Upload
**Classification:** CWE-434
**Source:** Nuclei Template (`ueditor-file-upload.yaml`)

## Description
UEditor contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ueditor/net/controller.ashx?action=catchimage&encode=utf-8
```

