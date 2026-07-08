# Vulnerability: Jupyter ipython - Authorization Bypass
**Classification:** CWE-288
**Source:** Nuclei Template (`jupyter-ipython-unauth.yaml`)

## Description
Jupyter was able to be accessed without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ipython/tree
```

