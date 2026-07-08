# Vulnerability: Dataease - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`dataease-default-login.yaml`)

## Description
Dataease has a built-in account demo/dataease, and many developers forget to delete or change the account password.
As a result, many Dataease can log in with this built-in account.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/api/auth/login
```

