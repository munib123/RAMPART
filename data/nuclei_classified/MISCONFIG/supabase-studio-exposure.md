# Vulnerability: Supabase Studio - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`supabase-studio-exposure.yaml`)

## Description
Supabase Studio (the official self-hosted Supabase admin dashboard) was detected exposed without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/project/default
GET {{BaseURL}}/api/platform/profile
```

