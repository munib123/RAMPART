# Nuclei Template: BlueImp jQuery-File-Upload - Arbitrary File Upload
**Template ID:** exposed-jquery-file-upload
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** Critical
**CWE:** CWE-434
**Source:** Nuclei Template (`exposed-jquery-file-upload.yaml`)

## Vulnerability Information & PoC

## Description
BlueImp jQuery-File-Upload does not require validation to upload files to the server and  does not exclude file types, which can lead to a remote code execution vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/jquery-file-upload/server/php/
```

## References
- https://www.exploit-db.com/exploits/45584
- https://github.com/blueimp/jQuery-File-Upload/blob/master/server/php/UploadHandler.php
