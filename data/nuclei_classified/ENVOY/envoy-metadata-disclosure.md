# Vulnerability: Envoy Proxy - Metadata Disclosure
**Classification:** ENVOY
**Source:** Nuclei Template (`envoy-metadata-disclosure.yaml`)

## Description
Detected misconfigured Envoy proxy instances that disclose sensitive information about the target infrastructure via the "x-envoy-peer-metadata" response header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

