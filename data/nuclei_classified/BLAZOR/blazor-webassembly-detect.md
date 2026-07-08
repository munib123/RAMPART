# Vulnerability: Blazor WebAssembly - Detect
**Classification:** BLAZOR
**Source:** Nuclei Template (`blazor-webassembly-detect.yaml`)

## Description
Blazor WebAssembly application was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_framework/blazor.boot.json
```

