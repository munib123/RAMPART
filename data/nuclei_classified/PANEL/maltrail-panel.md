# Vulnerability: Maltrail Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`maltrail-panel.yaml`)

## Description
Maltrail is a malicious traffic detection system, utilizing publicly available (black)lists containing malicious and/or generally suspicious trails, along with static trails compiled from various AV reports and custom user defined lists, where trail can be anything from domain name, URL (e.g. hXXp://109.162.38.120/harsh02.exe for known malicious executable), IP address (e.g. 185.130.5.231 for known attacker) or HTTP User-Agent header value.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

