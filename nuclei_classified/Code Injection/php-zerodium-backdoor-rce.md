# Nuclei Template: PHP 8.1.0-dev - Backdoor Remote Code Execution
**Template ID:** php-zerodium-backdoor-rce
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-94
**Source:** Nuclei Template (`php-zerodium-backdoor-rce.yaml`)

## Vulnerability Information & PoC

## Description
PHP 8.1.0-dev contains a backdoor dubbed 'zerodiumvar_dump' which can allow the execution of arbitrary PHP code.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://news-web.php.net/php.internals/113838
- https://flast101.github.io/php-8.1.0-dev-backdoor-rce/
- https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/revshell_php_8.1.0-dev.py
