# Vulnerability: Internet Archive User Search User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`internet-archive-user-search.yaml`)

## Description
Internet Archive User Search user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://archive.org/search.php?query={{user}}
```

