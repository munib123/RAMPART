# Vulnerability: Google Gemini API Key - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`google-gemini-key-exposure.yaml`)

## Description
Detects exposed Google API keys and verifies access to the Gemini Files API endpoint. Exploitation can result in unauthorized data exposure, quota exhaustion, and potential financial loss.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET https://generativelanguage.googleapis.com/v1beta/files?key={{google_api_key}}
```

