# Vulnerability: Webalizer Statistics Information Disclosure
**Classification:** WEBALIZER
**Source:** Nuclei Template (`webalizer-statistics.yaml`)

## Description
The remote host is running the Webalizer Report generator. Webalizer parses web logs and gives a potential attacker information regarding hosts that have accessed the server, resources accessed, total statistics for the Web server, version of Web server, and more.

## Secure Mitigation
Use ACLs to protect the Webalizer report.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/stats/index.html
```

