# Vulnerability: PHP 8.1.0-dev - Backdoor Remote Code Execution
**Classification:** CWE-94
**Source:** Nuclei Template (`php-zerodium-backdoor-rce.yaml`)

## Description
PHP 8.1.0-dev contains a backdoor dubbed 'zerodiumvar_dump' which can allow the execution of arbitrary PHP code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

