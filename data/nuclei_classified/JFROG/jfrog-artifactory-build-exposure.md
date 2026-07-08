# Vulnerability: JFrog Artifactory Build - Exposure
**Classification:** JFROG
**Source:** Nuclei Template (`jfrog-artifactory-build-exposure.yaml`)

## Description
Detected exposure of build information in JFrog Artifactory via unauthenticated API endpoints. Access to these endpoints may disclose sensitive data such as build names, numbers, CI/CD pipeline details, artifact paths, and internal infrastructure information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/artifactory/api/build
```

