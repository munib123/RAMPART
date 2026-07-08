# Vulnerability: Supabase Studio Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`supabase-studio-panel.yaml`)

## Description
Supabase Studio login panel was detected. The admin dashboard shipped with Supabase, the popular open-source Firebase alternative (Postgres + auth + realtime + storage + edge functions).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/_login
```

