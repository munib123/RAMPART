# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4465_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4465_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php
if (!empty($field['raw'])) {
    $string = $field['raw'];
} else {
    $value = Hash::extract($data, $field['path']);
    $string = empty($value[0]) ? '' : $value[0];
}
if (!empty($field['url'])) {
    if (!empty($field['url_vars'])) {
        if (!is_array($field['url_vars'])) {
            $field['url_vars'] = [$field['url_vars']];
        }
        foreach ($field['url_vars'] as $k => $path) {
            $field['url'] = str_replace('{{' . $k . '}}', $this->Hash->extract($data, $path)[0], $field['url']);
        }
    }
    $string = sprintf(
        '<a href="%s">%s</a>',
        h($field['url']),
        $string
    );
}
echo $string;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
     $string = $field['raw'];
 } else {
     $value = Hash::extract($data, $field['path']);
-    $string = empty($value[0]) ? '' : $value[0];
+    $string = empty($value[0]) ? '' : h($value[0]);
 }
 if (!empty($field['url'])) {
     if (!empty($field['url_vars'])) {
```
