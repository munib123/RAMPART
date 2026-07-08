# Vulnerability: Artifactory anonymous deploy
**Classification:** ARTIFACTORY
**Source:** Nuclei Template (`artifactory-anonymous-deploy.yaml`)

## Description
Artifactory anonymous repo is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/artifactory/ui/repodata?deploy=true
```

