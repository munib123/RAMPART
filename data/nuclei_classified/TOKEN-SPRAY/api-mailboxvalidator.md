# Vulnerability: MailboxValidator API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-mailboxvalidator.yaml`)

## Description
Validate email address to improve deliverability

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.mailboxvalidator.com/v1/email/free?email=test@test.com&key={{token}}
```

