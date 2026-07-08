# Vulnerability: Docker Daemon Exposed
**Classification:** DOCKER
**Source:** Nuclei Template (`docker-daemon-exposed.yaml`)

## Description
Docker Daemon exposed on the network map can help remote attacker to gain access to the Docker containers and potentially the host system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /version HTTP/1.1
Host: {{Hostname}}

GET /v{{version}}/containers/json HTTP/1.1
Host: {{Hostname}}
```

