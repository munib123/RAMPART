# Vulnerability: Apache Ambari Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`ambari-default-login.yaml`)

## Description
An Apache Ambari default admin login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v1/users/admin?fields=*,privileges/PrivilegeInfo/cluster_name,privileges/PrivilegeInfo/permission_name HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

