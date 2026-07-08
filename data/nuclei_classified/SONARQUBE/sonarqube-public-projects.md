# Vulnerability: Sonarqube with public projects
**Classification:** SONARQUBE
**Source:** Nuclei Template (`sonarqube-public-projects.yaml`)

## Description
Sonarqube public projects detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/components/suggestions?recentlyBrowsed=
```

