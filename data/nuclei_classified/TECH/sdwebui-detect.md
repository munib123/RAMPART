# Vulnerability: Stable Diffusion WebUI - Detect
**Classification:** TECH
**Source:** Nuclei Template (`sdwebui-detect.yaml`)

## Description
Detected AUTOMATIC1111 Stable Diffusion WebUI instance. SD WebUI was the mostpopular open-source interface for Stable Diffusion image generation. Exposed instancesmay allow unauthenticated access to image generation capabilities and model files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
```

