# Vulnerability: OpenHands Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`openhands-panel.yaml`)

## Description
OpenHands (formerly OpenDevin) was detected. OpenHands is an open-source AI software engineering agent platform that can write code, run commands, and perform development tasks autonomously. Exposed instances may allow unauthenticated access to the agent.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

