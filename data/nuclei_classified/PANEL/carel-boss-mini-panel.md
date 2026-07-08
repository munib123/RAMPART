# Vulnerability: CAREL Boss Mini - Login Panel Detected
**Classification:** PANEL
**Source:** Nuclei Template (`carel-boss-mini-panel.yaml`)

## Description
CAREL Boss Mini login panel was detected. Boss Mini is a local supervisor solution by CAREL used for monitoring and managing HVAC/R systems in commercial facilities. Exposed panels may indicate misconfigured network segmentation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/boss/
```

