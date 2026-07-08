# Vulnerability: BlueImp jQuery-File-Upload - Arbitrary File Upload
**Classification:** CWE-434
**Source:** Nuclei Template (`exposed-jquery-file-upload.yaml`)

## Description
BlueImp jQuery-File-Upload does not require validation to upload files to the server and  does not exclude file types, which can lead to a remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jquery-file-upload/server/php/
```

