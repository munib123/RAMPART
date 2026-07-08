# Vulnerability: Rockwell Automation FactoryTalk ViewPoint - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`rockwell-factorytalk-viewpoint-panel.yaml`)

## Description
Rockwell Automation FactoryTalk ViewPoint is a web-based HMI that allows remote
monitoring and control of industrial automation systems from a browser. It provides
access to FactoryTalk View Machine Edition and Site Edition displays. Exposed
instances may allow unauthorised access to industrial control system visualisations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

