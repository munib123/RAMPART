# Vulnerability: Oracle EBS SQL Log - Exposure
**Classification:** ORACLE
**Source:** Nuclei Template (`oracle-ebs-sqllog-exposure.yaml`)

## Description
Detected exposure of the sqlnet.log file in Oracle E-Business Suite (EBS), which often contained sensitive information such as database connection details, TNS entries, usernames, and error logs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/html/bin/sqlnet.log
GET {{BaseURL}}/OA_HTML/bin/sqlnet.log
```

