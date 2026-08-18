# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4794_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4794_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 46-68 of the vulnerable file.


$plugin_id = $sections[0];

if (!preg_match('/^[\w-]+$/', $plugin_id))
{
  die('Invalid plugin identifier');
}

if ( !isset($pwg_loaded_plugins[$plugin_id]) )
{
  die('Invalid URL - plugin '.$plugin_id.' not active');
}

$filename = PHPWG_PLUGINS_PATH.implode('/', $sections);
if (is_file($filename))
{
  include_once($filename);
}
else
{
  die('Missing file '.$filename);
}
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,6 +63,6 @@
 }
 else
 {
-  die('Missing file '.$filename);
+  die('Missing file '.htmlentities($filename));
 }
 ?>
```
