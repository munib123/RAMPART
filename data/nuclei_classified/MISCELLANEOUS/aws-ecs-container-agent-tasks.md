# Vulnerability: aws-ecs-container-agent-tasks
**Classification:** MISCELLANEOUS
**Source:** Nuclei Template (`aws-ecs-container-agent-tasks.yaml`)

## Description
Aws container metadata content

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v1/metadata
GET {{BaseURL}}/v1/tasks
```

