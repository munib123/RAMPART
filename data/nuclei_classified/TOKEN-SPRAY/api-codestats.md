# Vulnerability: CodeStats API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-codestats.yaml`)

## Description
Automatic time tracking for programmers

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://codestats.net/api/my/pulses HTTP/1.1
Host: codestats.net
X-API-Token: {{token}}

{
  "coded_at": "2016-04-24T01:43:56+12:00",
  "xps": [
    {"language": "C++",    "xp": 15},
    {"language": "Elixir", "xp": 30},
    {"language": "EEx",    "xp": 3}
  ]
}
```

