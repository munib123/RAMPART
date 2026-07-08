# Vulnerability: MongoDB HTTP Interface Enabled
**Classification:** MONGODB
**Source:** Nuclei Template (`file-mongodb-http-interface-enabled.yaml`)

## Description
Checks if the MongoDB HTTP interface is enabled in /etc/mongod.conf.

## Secure Mitigation
Set 'http.enabled: false' in /etc/mongod.conf and restart MongoDB.

