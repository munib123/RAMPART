# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1679_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1679_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1805-1845 of the vulnerable file.

            $error = 'errornoperm';
        }
        else if ($res_code == rcube_storage::READONLY) {
            $error = 'errorreadonly';
        }
        else if ($res_code == rcube_storage::OVERQUOTA) {
            $error = 'erroroverquota';
        }
        else if ($err_code && ($err_str = $this->storage->get_error_str())) {
            // try to detect access rights problem and display appropriate message
            if (stripos($err_str, 'Permission denied') !== false) {
                $error = 'errornoperm';
            }
            // try to detect full mailbox problem and display appropriate message
            // there can be e.g. "Quota exceeded" / "quotum would exceed" / "Over quota"
            else if (stripos($err_str, 'quot') !== false && preg_match('/exceed|over/i', $err_str)) {
                $error = 'erroroverquota';
            }
            else {
                $error = 'servererrormsg';
                $args  = array('msg' => $err_str);
            }
        }
        else if ($err_code < 0) {
            $error = 'storageerror';
        }
        else if ($fallback) {
            $error = $fallback;
            $args  = $fallback_args;
            $params['prefix'] = false;
        }

        if ($error) {
            if ($suffix && $this->text_exists($error . $suffix)) {
                $error .= $suffix;
            }

            $msg = $this->gettext(array('name' => $error, 'vars' => $args));

            if ($params['prefix'] && $fallback) {
                $msg = $this->gettext(array('name' => $fallback, 'vars' => $fallback_args)) . ' ' . $msg;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1822,7 +1822,7 @@
             }
             else {
                 $error = 'servererrormsg';
-                $args  = array('msg' => $err_str);
+                $args  = array('msg' => rcube::Q($err_str));
             }
         }
         else if ($err_code < 0) {
```
