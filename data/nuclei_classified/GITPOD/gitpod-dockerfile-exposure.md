# Vulnerability: Gitpod Dockerfile - Exposure
**Classification:** GITPOD
**Source:** Nuclei Template (`gitpod-dockerfile-exposure.yaml`)

## Description
Detected exposed .gitpod.Dockerfile files. These files define the development environment and may disclose installed software versions, internal paths, or potentially hardcoded secrets.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.gitpod.Dockerfile
GET {{BaseURL}}/.gitpod.dockerfile
```

