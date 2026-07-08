# Vulnerability: Gerrit Code Review - Account Enumeration
**Classification:** GERRIT
**Source:** Nuclei Template (`gerrit-account-enum.yaml`)

## Description
Gerrit Code Review exposes the /accounts/ REST API endpoint which can be used to enumerate user accounts.The endpoint allows querying for accounts by username, email, or name, potentially revealing sensitive user information including account IDs, names, emails, and usernames without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/accounts/?q=a&n=10
GET {{BaseURL}}/accounts/?suggest&q=a&n=10
```

