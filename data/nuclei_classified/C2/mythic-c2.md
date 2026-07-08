# Vulnerability: Mythic C2 - Detect
**Classification:** C2
**Source:** Nuclei Template (`mythic-c2.yaml`)

## Description
A cross-platform, post-exploit, red teaming framework built with python3, docker, docker-compose, and a web browser UI.
It's designed to provide a collaborative and user friendly interface for operators, managers, and reporting throughout red teaming.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/new/login
```

