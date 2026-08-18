# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4969_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4969_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 73-100 of the vulnerable file.

     *                         '$2$s' is replaced by the error message.
     *                         '$3$d' is replaced by the error code.
     *                         '$4$s' is replaced by the string that caused the
     *                                issue.
     *                         '$5$d' is replaced by the position of the string.
     * @return array
     */
    public static function format(
        $errors,
        $format = '#%1$d: %2$s (near "%4$s" at position %5$d)'
    ) {
        $ret = array();

        $i = 0;
        foreach ($errors as $key => $err) {
            $ret[$key] = sprintf(
                $format,
                ++$i,
                $err[0],
                $err[1],
                $err[2],
                $err[3]
            );
        }

        return $ret;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,7 +90,7 @@
                 ++$i,
                 $err[0],
                 $err[1],
-                $err[2],
+                htmlspecialchars($err[2]),
                 $err[3]
             );
         }
```
