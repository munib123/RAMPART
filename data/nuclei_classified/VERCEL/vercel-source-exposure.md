# Vulnerability: Vercel Source Code Exposure
**Classification:** VERCEL
**Source:** Nuclei Template (`vercel-source-exposure.yaml`)

## Description
The Vercel Source Code Exposure misconfiguration allows an attacker to access sensitive source code files on the Vercel platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_src
```

