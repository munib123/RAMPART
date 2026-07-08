# Vulnerability: Apache Mesos - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apache-mesos-panel.yaml`)

## Description
Apache Mesos panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}:5050
```

