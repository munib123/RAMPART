# Vulnerability: Next.js / Vite Public ENV Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`nextjs-vite-public-env.yaml`)

## Description
Identified public environment variables exposed to the client in Next.js (__NEXT_DATA__.env) and Vite applications through runtime configurations.
Extended to detect any exposed Supabase URL on the page, regardless of variable name.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

