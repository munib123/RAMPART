# Vulnerability: Sangfor Next-Generation Application Firewall (NGAF) - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`sangfor-ngaf-panel.yaml`)

## Description
Sangfor NGAF is a next-generation application firewall and SSL VPN gateway by
Sangfor Technologies. It is widely deployed in APAC and China-based enterprises.
The management portal is frequently exposed on non-standard ports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

