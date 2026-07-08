# Vulnerability: Oracle EBS - SQL Log Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`oracle-ebs-sqllog-disclosure.yaml`)

## Description
An Oracle EBS SQL log was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/OA_HTML/bin/sqlnet.log
```

