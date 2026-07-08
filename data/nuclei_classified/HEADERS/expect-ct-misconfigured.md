# Vulnerability: Expect-CT Header - Misconfigured
**Classification:** HEADERS
**Source:** Nuclei Template (`expect-ct-misconfigured.yaml`)

## Description
Detected misconfigured Expect-CT headers: max-age is 0 (ineffective) and enforce directive is missing

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

