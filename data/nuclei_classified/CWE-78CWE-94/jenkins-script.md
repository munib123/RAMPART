# Vulnerability: Jenkins - Remote Code Execution
**Classification:** CWE-78,CWE-94
**Source:** Nuclei Template (`jenkins-script.yaml`)

## Description
Jenkins is susceptible to a remote code execution vulnerability due to accessible script functionality.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/script/
GET {{BaseURL}}/jenkins/script
```

