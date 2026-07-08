# Vulnerability: Node.js REPL History Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`node-repl-history-disclosure.yaml`)

## Description
The Node.js REPL history file (.node_repl_history) was exposed, which had contained a log of commands entered into the Node.js interactive shell.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.node_repl_history
GET {{BaseURL}}/node_repl_history
```

