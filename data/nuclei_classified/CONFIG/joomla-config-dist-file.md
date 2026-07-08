# Vulnerability: Joomla! Configuration File - Detect
**Classification:** CONFIG
**Source:** Nuclei Template (`joomla-config-dist-file.yaml`)

## Description
Joomla! configuration.php-dist file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/configuration.php-dist
```

