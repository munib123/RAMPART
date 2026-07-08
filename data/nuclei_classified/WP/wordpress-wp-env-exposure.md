# Vulnerability: WordPress Configuration wp-env - Exposure
**Classification:** WP
**Source:** Nuclei Template (`wordpress-wp-env-exposure.yaml`)

## Description
Detected the WordPress wp-env.json configuration file publicly accessible, potentially revealing the PHP version, installed plugins, themes, and development environment details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.wp-env.json
```

