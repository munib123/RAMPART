# Vulnerability: Unauthorized HP Printer
**Classification:** HP
**Source:** Nuclei Template (`unauthorized-hp-printer.yaml`)

## Description
HP Printer is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SSI/Auth/ip_snmp.htm
```

