# Vulnerability: Docker Container - Misconfiguration Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`misconfigured-docker.yaml`)

## Description
A Docker container misconfiguration was discovered. The Docker daemon can listen for Docker Engine API requests via three different types of Socket - unix, tcp, and fd. With tcp enabled, the default setup provides un-encrypted and un-authenticated direct access to the Docker daemon. It is conventional to use port 2375 for un-encrypted, and port 2376 for encrypted communication with the daemon.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/images/json
```

