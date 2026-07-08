# Vulnerability: SuperAGI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`superagi-panel.yaml`)

## Description
SuperAGI panel was detected. SuperAGI was an open-source autonomous AI agent platform that enables building, managing, and running AI agents. Exposed instances may allow unauthorized access to agent configurations and execution environments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
```

