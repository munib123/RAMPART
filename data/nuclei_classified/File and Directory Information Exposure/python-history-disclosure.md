# Nuclei Template: Python History File Disclosure
**Template ID:** python-history-disclosure
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Low
**CWE:** CWE-538
**Source:** Nuclei Template (`python-history-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Detected exposed .python_history files on web servers.These files contained Python REPL command history that could have leaked sensitive information such as credentials, API keys, internal paths, database queries, and system commands.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.python_history
```

