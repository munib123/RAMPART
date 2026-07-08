# Vulnerability: Laravel Telescope Disclosure
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-telescope.yaml`)

## Description
Telescope provides insight into the requests coming into your application, exceptions, log entries, database queries, queued jobs, mail, notifications, cache operations, scheduled tasks, variable dumps, and more.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/telescope/requests
```

