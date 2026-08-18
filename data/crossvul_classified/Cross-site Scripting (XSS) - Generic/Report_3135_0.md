# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3135_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3135_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 199-239 of the vulnerable file.

  if ('f' != $_GET['part'] and isset( $_SERVER['HTTP_IF_MODIFIED_SINCE'] ) )
  {
    set_status_header(304);
    foreach ($http_headers as $header)
    {
      header( $header );
    }
    exit();
  }
}

if (!isset($ctype))
{ // give it a guess
  $ctype = guess_mime_type( get_extension($file) );
}

$http_headers[] = 'Content-Type: '.$ctype;

if (isset($_GET['download']))
{
  $http_headers[] = 'Content-Disposition: attachment; filename="'.$element_info['file'].'";';
  $http_headers[] = 'Content-Transfer-Encoding: binary';
}
else
{
  $http_headers[] = 'Content-Disposition: inline; filename="'
            .basename($file).'";';
}

foreach ($http_headers as $header)
{
  header( $header );
}

// Looking at the safe_mode configuration for execution time
if (ini_get('safe_mode') == 0)
{
  @set_time_limit(0);
}

@readfile($file);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -216,7 +216,7 @@
 
 if (isset($_GET['download']))
 {
-  $http_headers[] = 'Content-Disposition: attachment; filename="'.$element_info['file'].'";';
+  $http_headers[] = 'Content-Disposition: attachment; filename="'.htmlspecialchars_decode($element_info['file']).'";';
   $http_headers[] = 'Content-Transfer-Encoding: binary';
 }
 else
```
