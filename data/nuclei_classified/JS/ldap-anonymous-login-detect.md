# Vulnerability: LDAP Anonymous Login - Detect
**Classification:** JS
**Source:** Nuclei Template (`ldap-anonymous-login-detect.yaml`)

## Description
Detects whether an LDAP server allows anonymous bind (login without credentials). Anonymous access can expose sensitive directory information and should be restricted
unless explicitly intended.

