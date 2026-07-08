# Vulnerability: Atom remote-ssh ftpconfig Exposure
**Classification:** ATOM
**Source:** Nuclei Template (`ftpconfig.yaml`)

## Description
Created by remote-ssh for Atom, contains SFTP/SSH server details and credentials

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.ftpconfig
```

