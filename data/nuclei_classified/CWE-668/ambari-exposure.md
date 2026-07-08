# Vulnerability: Apache Ambari Exposure Admin Login Panel
**Classification:** CWE-668
**Source:** Nuclei Template (`ambari-exposure.yaml`)

## Description
An Apache Ambari panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

