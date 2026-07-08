# Vulnerability: Tugboat Configuration File Exposure
**Classification:** TUGBOAT
**Source:** Nuclei Template (`tugboat-config-exposure.yaml`)

## Description
A Tugboat configuration file was discovered. Tugboat is a command line tool for interacting with DigitalOcean droplets.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.tugboat
```

