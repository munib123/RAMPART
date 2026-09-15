# Nuclei Template: Jupyter ipython - Authorization Bypass
**Template ID:** jupyter-ipython-unauth
**Vulnerability Class:** Authentication Bypass Using an Alternate Path or Channel
**Severity:** Critical
**CWE:** CWE-288
**Source:** Nuclei Template (`jupyter-ipython-unauth.yaml`)

## Vulnerability Information & PoC

## Description
Jupyter was able to be accessed without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ipython/tree
```

