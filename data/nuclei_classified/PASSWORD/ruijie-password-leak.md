# Vulnerability: RG-UAC Ruijie - Password Hashes Leak
**Classification:** PASSWORD
**Source:** Nuclei Template (`ruijie-password-leak.yaml`)

## Description
Multiple Firewall Devices from vendor Ruijie Networks are affected by an information leakage vulnerability where credentials are included in the source code of the web admin login interface (usernames, roles, MD5 hashes and additional details of each user). Attackers can use this information to illegally access into the vulnerable devices, obtain sensitive device information and change configurations. The vulnerability is identified by CNVD-2021-14536.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

