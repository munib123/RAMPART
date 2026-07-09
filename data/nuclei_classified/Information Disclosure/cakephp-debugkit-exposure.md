# Nuclei Template: CakePHP - Debug Kit Toolbar Exposure
**Template ID:** cakephp-debugkit-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`cakephp-debugkit-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected CakePHP Debug Kit toolbar, potentially leaking sensitive application information, database queries, and configuration.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/debug-kit
```

## References
- https://github.com/cakephp/debug_kit
- https://book.cakephp.org/debugkit/
