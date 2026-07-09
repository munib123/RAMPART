# Nuclei Template: Sidekiq Dashboard Panel - Detect
**Template ID:** sidekiq-dashboard
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`sidekiq-dashboard.yaml`)

## Vulnerability Information & PoC

## Description
Sidekiq Dashboard panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/sidekiq
```

## References
- https://sidekiq.org
- https://github.com/mperham/sidekiq
- https://github.com/mperham/sidekiq/wiki/Monitoring
