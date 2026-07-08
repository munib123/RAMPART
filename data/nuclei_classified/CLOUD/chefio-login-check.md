# Vulnerability: Chef.io Login Check
**Classification:** CLOUD
**Source:** Nuclei Template (`chefio-login-check.yaml`)

## Description
Checks for a valid chef.io account.

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.chef.io/login HTTP/1.1
Host: api.chef.io
Content-Type: application/x-www-form-urlencoded

utf8=%E2%9C%93&authenticity_token=&authenticity_token=&to=https://api.chef.io/login-success&username={{username}}&password={{password}}&commit=Sign+In
```

