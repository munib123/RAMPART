# Vulnerability: FTP Deployment Config File - Exposure
**Classification:** CONFIG
**Source:** Nuclei Template (`deployment-ini.yaml`)

## Description
Config file for "FTP deployment" utility usually contains server's FTP credentials in plain text.

## Secure Mitigation
Delete the config file from server & add it to `ignore` section of the deployment file. Or block access to the file using `.htaccess` on the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

