# Vulnerability: Browserless API Swagger - Detect
**Classification:** TECH
**Source:** Nuclei Template (`browserless-swagger-detect.yaml`)

## Description
Detects exposed Browserless API Swagger UI interface. Browserless is a headless browser automation service that provides REST APIs for Chrome/Chromium-based browser operations including screenshots, PDFs, and web scraping.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/docs/swagger-ui-init.js
GET {{BaseURL}}/docs
```

