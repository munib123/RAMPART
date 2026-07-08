# Vulnerability: Jenkins Dashboard - Unauthenticated Access
**Classification:** JENKINS
**Source:** Nuclei Template (`unauthenticated-jenkins.yaml`)

## Description
Jenkins Dashboard is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/jenkins/
```

