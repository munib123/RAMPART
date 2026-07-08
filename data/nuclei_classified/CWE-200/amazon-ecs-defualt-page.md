# Vulnerability: Amazon ECS Sample App Default Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`amazon-ecs-defualt-page.yaml`)

## Description
Amazon ECS Sample App Default Page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

