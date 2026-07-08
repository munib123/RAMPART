# Vulnerability: InsaneJournal User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`insanejournal.yaml`)

## Description
InsaneJournal user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.insanejournal.com/profile
```

