# Vulnerability: Password Expiry Setting Check
**Classification:** CODE
**Source:** Nuclei Template (`password-never-expires.yaml`)

## Description
Ensure the "Password never expires" setting is disabled for all active user accounts so that password expiration policies can be enforced effectively.

## Secure Mitigation
Disable the "Password never expires" setting using one of the following methods:
- Command Line: > wmic useraccount where name="USERNAME" set passwordexpires=true
- GUI: Use Local Security Policy to modify the user account settings accordingly.

