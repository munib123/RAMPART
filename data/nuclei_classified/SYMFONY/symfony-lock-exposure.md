# Vulnerability: Symfony Lock File - Exposure
**Classification:** SYMFONY
**Source:** Nuclei Template (`symfony-lock-exposure.yaml`)

## Description
symfony.lock was found accessible, exposing a full list of installed Composer packages, library versions, and metadata for a Symfony-based PHP application. Disclosure of this file can provide insight into the application's attack surface, potentially revealing vulnerable or outdated dependencies and aiding an attacker in choosing their exploit strategy.

## Secure Mitigation
Restrict direct access to internal and sensitive files such as symfony.lock via proper web server configuration (e.g., .htaccess, nginx directives) and consider excluding such files from the web root in deployment.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/symfony.lock
```

