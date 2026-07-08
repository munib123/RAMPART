# Vulnerability: DockerHub User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dockerhub.yaml`)

## Description
DockerHub user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hub.docker.com/v2/users/{{user}}/
```

