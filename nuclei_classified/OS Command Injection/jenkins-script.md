# Nuclei Template: Jenkins - Remote Code Execution
**Template ID:** jenkins-script
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`jenkins-script.yaml`)

## Vulnerability Information & PoC

## Description
Jenkins is susceptible to a remote code execution vulnerability due to accessible script functionality.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/script/
GET {{BaseURL}}/jenkins/script
```

## References
- https://hackerone.com/reports/403402
- https://medium.com/@gokulsspace/the-30000-bounty-affair-3f025ee6b834
