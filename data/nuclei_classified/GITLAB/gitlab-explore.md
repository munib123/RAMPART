# Vulnerability: GitLab Instance Explore - Detect
**Classification:** GITLAB
**Source:** Nuclei Template (`gitlab-explore.yaml`)

## Description
This template checks for GitLab instances by verifying if /explore and /api/v4/projects endpoints are accessible with a 200 response.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/explore
GET {{BaseURL}}/api/v4/projects
```

