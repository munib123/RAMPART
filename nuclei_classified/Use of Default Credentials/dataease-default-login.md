# Nuclei Template: Dataease - Default Login
**Template ID:** dataease-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`dataease-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Dataease has a built-in account demo/dataease, and many developers forget to delete or change the account password.
As a result, many Dataease can log in with this built-in account.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/api/auth/login
```

## References
- https://github.com/dataease/dataease/issues/5995
