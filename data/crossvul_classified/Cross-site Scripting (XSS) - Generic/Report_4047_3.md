# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4047_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4047_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2342-2377 of the vulnerable file.

}

// Return mimetypes supported by the browser
function rcmail_supported_mimetypes()
{
    $rcmail = rcube::get_instance();

    // mimetypes supported by the browser (default settings)
    $mimetypes = (array) $rcmail->config->get('client_mimetypes');

    // Remove unsupported types, which makes that attachment which cannot be
    // displayed in a browser will be downloaded directly without displaying an overlay page
    if (empty($_SESSION['browser_caps']['pdf']) && ($key = array_search('application/pdf', $mimetypes)) !== false) {
        unset($mimetypes[$key]);
    }

    if (empty($_SESSION['browser_caps']['flash']) && ($key = array_search('application/x-shockwave-flash', $mimetypes)) !== false) {
        unset($mimetypes[$key]);
    }

    foreach (array('tiff', 'webp') as $type) {
        if (empty($_SESSION['browser_caps'][$type]) && ($key = array_search('image/' . $type, $mimetypes)) !== false) {
            // can we convert it to jpeg?
            if (!rcube_image::is_convertable('image/' . $type)) {
                unset($mimetypes[$key]);
            }
        }
    }

    // @TODO: support mail preview for compose attachments
    if ($rcmail->action != 'compose' && !in_array('message/rfc822', $mimetypes)) {
        $mimetypes[] = 'message/rfc822';
    }

    return array_values($mimetypes);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2359,6 +2359,11 @@
         unset($mimetypes[$key]);
     }
 
+    // We cannot securely preview XML files as we do not have a proper parser
+    if (($key = array_search('text/xml', $mimetypes)) !== false) {
+        unset($mimetypes[$key]);
+    }
+
     foreach (array('tiff', 'webp') as $type) {
         if (empty($_SESSION['browser_caps'][$type]) && ($key = array_search('image/' . $type, $mimetypes)) !== false) {
             // can we convert it to jpeg?
```
