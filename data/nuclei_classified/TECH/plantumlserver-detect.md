# Vulnerability: PlantUMLServer - Detect
**Classification:** TECH
**Source:** Nuclei Template (`plantumlserver-detect.yaml`)

## Description
PlantUMLServer is an open-source web application that renders UML diagrams from textual descriptions. It provides a web interface for the PlantUML diagram generation tool, allowing users to create various types of diagrams including class diagrams, sequence diagrams, and activity diagrams through a simple markup language.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

