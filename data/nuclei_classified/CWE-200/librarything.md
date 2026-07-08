# Vulnerability: LibraryThing User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`librarything.yaml`)

## Description
LibraryThing user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.librarything.com/profile/{{user}}
```

