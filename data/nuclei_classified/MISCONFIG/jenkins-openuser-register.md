# Vulnerability: Jenkins Open User registration
**Classification:** MISCONFIG
**Source:** Nuclei Template (`jenkins-openuser-register.yaml`)

## Description
The Jenkins allows registering a new user and accessing the dashboard.

## Secure Mitigation
Its recommended to turn off user registration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/signup
```

