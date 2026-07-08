# Vulnerability: MongoDB SSL Disabled
**Classification:** MONGODB
**Source:** Nuclei Template (`file-mongodb-ssl-disabled.yaml`)

## Description
Ensures MongoDB uses SSL/TLS for secure connections.

## Secure Mitigation
Set 'net.ssl.mode: requireSSL' and define 'PEMKeyFile' in /etc/mongod.conf.

