# Vulnerability: SeaCMS V6.4.5 RCE
**Classification:** SEACMS
**Source:** Nuclei Template (`seacms-rce.yaml`)

## Description
A vulnerability in SeaCMS allows remote unauthenticated attackers to execute arbitrary PHP code.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/search.php?searchtype=5
```

