# Vulnerability: WordPress User Registration Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wp-registration-enabled.yaml`)

## Description
WordPress user registration is currently configured so that anyone can register as a user, thereby enabling an attacker to possibly access sensitive data and execute unathorized operations.

## Secure Mitigation
Disable user registration if not needed. To do so, log in as an administrator and go to Settings -> General and uncheck "Anyone can register."

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-login.php
```

