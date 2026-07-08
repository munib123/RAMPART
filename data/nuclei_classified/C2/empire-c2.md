# Vulnerability: Empire C2 - Detect
**Classification:** C2
**Source:** Nuclei Template (`empire-c2.yaml`)

## Description
Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers. The Empire server is written in Python 3 and is modular to allow operator flexibility. Empire comes built-in with a client that can be used remotely to access the server. There is also a GUI available for remotely accessing the Empire server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

