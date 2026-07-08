# Vulnerability: Trello API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-trello.yaml`)

## Description
Boards, lists and cards to help you organize and prioritize your projects

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.trello.com/1/members/me?key={{key}}&token={{token}}
```

