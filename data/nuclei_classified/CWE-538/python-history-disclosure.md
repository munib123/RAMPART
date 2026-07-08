# Vulnerability: Python History File Disclosure
**Classification:** CWE-538
**Source:** Nuclei Template (`python-history-disclosure.yaml`)

## Description
Detected exposed .python_history files on web servers.These files contained Python REPL command history that could have leaked sensitive information such as credentials, API keys, internal paths, database queries, and system commands.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.python_history
```

