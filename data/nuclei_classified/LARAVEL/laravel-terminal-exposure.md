# Vulnerability: Laravel Terminal - Exposed
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-terminal-exposure.yaml`)

## Description
The web application was built on the Laravel framework, with Laravel Terminal enabled and publicly accessible; this was detected in the production environment and led to disclosure of sensitive application information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/asf/terminal
```

