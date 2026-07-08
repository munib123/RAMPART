# Vulnerability: Google Calendar - Exposure
**Classification:** GOOGLE
**Source:** Nuclei Template (`google-calendar-exposure.yaml`)

## Description
Detected publicly accessible Google Calendar embedded on the target that may expose sensitive information including meeting details, attendee names, event schedules, and internal organizational data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

