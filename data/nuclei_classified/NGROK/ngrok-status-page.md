# Vulnerability: Ngrok Status Page
**Classification:** NGROK
**Source:** Nuclei Template (`ngrok-status-page.yaml`)

## Description
Ngrok is a popular platform that provides secure tunnels to localhost, allowing users to expose a local web server to the internet.The Ngrok status page is a web page that provides real-time information about the health and performance of the Ngrok service.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/status
```

