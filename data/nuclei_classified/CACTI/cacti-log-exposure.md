# Vulnerability: Cacti Log - Exposure
**Classification:** CACTI
**Source:** Nuclei Template (`cacti-log-exposure.yaml`)

## Description
Exposed Cacti log files (cacti.log) were detected. These files contain system statistics, error messages, and potentially sensitive information. They can also be used in log poisoning attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cacti/log/cacti.log
GET {{BaseURL}}/log/cacti.log
GET {{BaseURL}}/cacti.log
GET {{BaseURL}}/include/cacti.log
```

