# Vulnerability: IBM iNotes Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ibm-note-login.yaml`)

## Description
IBM iNotes login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/names.nsf
GET {{BaseURL}}/webredir.nsf
```

