# Vulnerability: WordPress Plugin WPML Version < 4.6.1 Cross-Site Scripting
**Classification:** XSS
**Source:** Nuclei Template (`wpml-xss.yaml`)

## Description
WordPress Plugin WPML Version < 4.6.1  is vulnerable to RXSS via wp_lang parameter.

## Secure Mitigation
Update the WPML plugin to 4.6.1 version.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-login.php?wp_lang=en_US%27
```

