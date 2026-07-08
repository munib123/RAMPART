# Vulnerability: Taskrabbit User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`taskrabbit.yaml`)

## Description
Taskrabbit user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.taskrabbit.com/profile/{{user}}/about
```

