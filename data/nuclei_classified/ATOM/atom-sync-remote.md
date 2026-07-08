# Vulnerability: Atom Synchronization Exposure
**Classification:** ATOM
**Source:** Nuclei Template (`atom-sync-remote.yaml`)

## Description
It discloses username and password created by remote-sync for Atom, contains FTP and/or SCP/SFTP/SSH server details and credentials

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.remote-sync.json
```

