# Vulnerability: Secure Access Gateway SecSSLVPN - Authentication Bypass
**Classification:** SECSSLVPN
**Source:** Nuclei Template (`secsslvpn-auth-bypass.yaml`)

## Description
The Secure Access Gateway SecSSL 3600 secure access gateway system has an unauthorized access vulnerability. An attacker can obtain the user list and modify the user account password through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/group/x_group.php?id=1
```

