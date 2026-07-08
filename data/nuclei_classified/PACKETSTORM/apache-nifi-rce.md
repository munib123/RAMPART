# Vulnerability: Apache NiFi - Remote Code Execution
**Classification:** PACKETSTORM
**Source:** Nuclei Template (`apache-nifi-rce.yaml`)

## Description
Apache NiFi is designed for data streaming. It supports highly configurable data routing, transformation, and system mediation logic that indicate graphs. The system has unauthorized remote command execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nifi-api/process-groups/root
```

