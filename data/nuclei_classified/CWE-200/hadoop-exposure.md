# Vulnerability: Apache Hadoop Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hadoop-exposure.yaml`)

## Description
Apache Hadoop panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dfshealth.html
```

