# Vulnerability: GolangCI-Lint Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`golangci-config.yaml`)

## Description
GolangCI-Lint configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.golangci.yml
GET {{BaseURL}}/.golangci.yaml
GET {{BaseURL}}/.golangci.toml
GET {{BaseURL}}/.golangci.json
```

