# Vulnerability: RStudio Sign In Panel - Detect
**Classification:** RSTUDIO
**Source:** Nuclei Template (`rstudio-panel.yaml`)

## Description
RStudio Sign In panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth-sign-in?appUri=%2F
```

