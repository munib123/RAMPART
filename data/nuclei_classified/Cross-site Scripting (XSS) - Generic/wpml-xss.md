# Nuclei Template: WordPress Plugin WPML Version < 4.6.1 Cross-Site Scripting
**Template ID:** wpml-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`wpml-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Plugin WPML Version < 4.6.1  is vulnerable to RXSS via wp_lang parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-login.php?wp_lang=en_US%27
```

## Remediation
Update the WPML plugin to 4.6.1 version.

## References
- https://wpml.org/fr/changelog/2023/03/wpml-4-6-1-important-security-update/
- https://twitter.com/bug_vs_me/status/1652789903766200320
