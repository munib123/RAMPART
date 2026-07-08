# Vulnerability: Label Studio - Sign-up Detect
**Classification:** LABEL-STUDIO
**Source:** Nuclei Template (`label-studio-signup.yaml`)

## Description
Detects the presence of the Label Studio sign-up.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /user/signup HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

