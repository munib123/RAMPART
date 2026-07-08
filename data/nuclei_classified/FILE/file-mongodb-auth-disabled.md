# Vulnerability: MongoDB Authentication Disabled
**Classification:** FILE
**Source:** Nuclei Template (`file-mongodb-auth-disabled.yaml`)

## Description
Detects if MongoDB authentication is disabled or missing in mongod.conf. If 'authorization: enabled' is missing under 'security:', authentication is not enforced.

