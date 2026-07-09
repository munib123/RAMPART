# Nuclei Template: Drupal 7 Elfinder - Remote Code Execution
**Template ID:** drupal7-elfinder-rce
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** Critical
**CWE:** CWE-434
**Source:** Nuclei Template (`drupal7-elfinder-rce.yaml`)

## Vulnerability Information & PoC

## Description
Identifies Drupal sites with the elfinder library installed, which could be vulnerable to unrestricted file upload through the connector.php file.When this component is detected, the site may be vulnerable to remote code execution attacks via PHP file uploads.This template only detects the presence of the vulnerable component and does not perform any exploitation.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/sites/all/libraries/elfinder/connectors/php/connector.php
```

## Remediation
Remove the elfinder library if not needed, or implement proper file upload restrictions and input validation. Additionally, consider implementing Web Application Firewall rules to block access to the connector.php file.

## References
- https://github.com/Kro0oz/drupal-7-elfinder
