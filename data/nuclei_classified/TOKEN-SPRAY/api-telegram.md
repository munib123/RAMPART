# Vulnerability: Telegram API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-telegram.yaml`)

## Description
Telegram bot API token

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.telegram.org/bot{{token}}/getMe
```

