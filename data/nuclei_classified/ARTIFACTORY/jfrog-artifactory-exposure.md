# Vulnerability: JFrog Artifactory Artifacts Exposure
**Classification:** ARTIFACTORY
**Source:** Nuclei Template (`jfrog-artifactory-exposure.yaml`)

## Description
JFrog Artifactory Artifact repository was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/artifactory/api/repositories
```

