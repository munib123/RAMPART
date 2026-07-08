# Vulnerability: GoIP GSM VoIP Gateway - Default Password
**Classification:** CWE-522
**Source:** Nuclei Template (`goip-default-login.yaml`)

## Description
GoIP GSM VoIP Gateway Default Password, Allows attackers to send, receive sms and calls.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /default/en_US/status.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

