# Vulnerability: Defacement Content - Detection
**Classification:** MISC
**Source:** Nuclei Template (`defacement-detect.yaml`)

## Description
This template detects defacement content in the response body, using a list of commom paths as payload.It also detects spamdexing and hacktivism signatures and extracts a text snippet with the match.The URL paths and regex rules were based on research from several sources.Other rules are based in the author's experience and are not exhaustive.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{path}}
```

