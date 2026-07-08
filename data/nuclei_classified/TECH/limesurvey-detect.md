# Vulnerability: LimeSurvey Survey Software - Detect
**Classification:** TECH
**Source:** Nuclei Template (`limesurvey-detect.yaml`)

## Description
Limesurvey is the number one open-source survey software. Advanced features like branching and multiple question types make it a valuable partner for survey-creation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

