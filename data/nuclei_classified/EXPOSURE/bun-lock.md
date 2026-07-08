# Vulnerability: Bun Lock File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`bun-lock.yaml`)

## Description
The bun.lockb file is similar to the package-lock.json file used by npm or the yarn.lock file used by Yarn. It serves as a lock file that ensures consistent and reproducible installations of dependencies across different environments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bun.lockb
```

