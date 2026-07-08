# Vulnerability: Gitea - User Enumeration
**Classification:** TECH
**Source:** Nuclei Template (`gitea-userenum.yaml`)

## Description
Enumerates the users registered in the Gitea web application, a self-hosted all-in-one software development service, including Git hosting, code review, team collaboration, package registry and CI/CD.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/explore/users/sitemap-1.xml
```

