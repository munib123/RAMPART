# Vulnerability: Voilà Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`voila-panel.yaml`)

## Description
Voilà is an open-source tool that turns Jupyter Notebooks into standalone web applications.
It is commonly used to share AI/ML dashboards and interactive data science tools.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

