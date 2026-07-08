# Vulnerability: Jira Unauthenticated Installed gadgets
**Classification:** ATLASSIAN
**Source:** Nuclei Template (`jira-unauthenticated-installed-gadgets.yaml`)

## Description
Some Jira instances allow to read the installed gadgets (sometimes it's also possible to read config xml file for some gadgets)

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/rest/config/1.0/directory
```

