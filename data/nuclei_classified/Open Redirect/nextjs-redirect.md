# Nuclei Template: Next.js <1.2.3 - Open Redirect
**Template ID:** nextjs-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`nextjs-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Next.js contains an open redirect via “_next/image” due to improper path parsing.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/_next/image?url=/\/\interact.sh/&q=100&w=128&h=128
```

## Remediation
Upgrade to Next.js version 1.2.3 or higher.

## References
- https://github.com/netlify/netlify-ipx/security/advisories/GHSA-9jjv-524m-jm98
- https://samcurry.net/universal-xss-on-netlifys-next-js-library/
