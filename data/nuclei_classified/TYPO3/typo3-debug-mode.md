# Vulnerability: TYPO3 Debug Mode Enabled
**Classification:** TYPO3
**Source:** Nuclei Template (`typo3-debug-mode.yaml`)

## Description
TYPO3 Debug Mode is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

