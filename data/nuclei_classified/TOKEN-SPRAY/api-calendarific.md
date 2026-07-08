# Vulnerability: Calendarific API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-calendarific.yaml`)

## Description
Worldwide Holidays

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://calendarific.com/api/v2/holidays?api_key={{token}}&country=US&year=2021
```

