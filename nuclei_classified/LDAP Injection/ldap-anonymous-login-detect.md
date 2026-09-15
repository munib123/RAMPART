# Nuclei Template: LDAP Anonymous Login - Detect
**Template ID:** ldap-anonymous-login-detect
**Vulnerability Class:** LDAP Injection
**Severity:** Medium
**Source:** Nuclei Template (`ldap-anonymous-login-detect.yaml`)

## Vulnerability Information & PoC

## Description
Detects whether an LDAP server allows anonymous bind (login without credentials). Anonymous access can expose sensitive directory information and should be restricted
unless explicitly intended.

## References
- https://ldap.com/ldapv3-wire-protocol-reference-bind/#anonymous
- https://docs.projectdiscovery.io/templates/protocols/javascript/modules/ldap.Client#getadgroups
