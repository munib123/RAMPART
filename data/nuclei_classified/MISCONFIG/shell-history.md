# Vulnerability: Shell History
**Classification:** MISCONFIG
**Source:** Nuclei Template (`shell-history.yaml`)

## Description
Discover history for bash, ksh, sh, and zsh

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.bash_history
GET {{BaseURL}}/.ksh_history
GET {{BaseURL}}/.sh_history
GET {{BaseURL}}/.zsh_history
```

