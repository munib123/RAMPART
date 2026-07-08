# Vulnerability: Yarn Lock File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`yarn-lock.yaml`)

## Description
The yarn.lock file stores the versions of each Yarn dependency installed. It's a lock file for package.json.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/yarn.lock
```

