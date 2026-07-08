# Vulnerability: ComfyUI - Detect
**Classification:** TECH
**Source:** Nuclei Template (`comfyui-detect.yaml`)

## Description
Detected ComfyUI, a node-based Stable Diffusion workflow editor. Custom nodes can execute arbitrary code without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

