# Vulnerability: MongoDB Audit Logging Disabled
**Classification:** MONGODB
**Source:** Nuclei Template (`file-mongodb-audit-log-disabled.yaml`)

## Description
Ensures MongoDB audit logging is enabled.

## Secure Mitigation
Set 'auditLog.destination: file' and specify 'path' in /etc/mongod.conf.

