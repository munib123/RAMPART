# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5158_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5158_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 52-90 of the vulnerable file.

            if (isset($options[1]) && !empty($options[1])) {
                foreach ($fields_meta as $key => $val) {
                    if ($val->name == $options[1]) {
                        $pos = $key;
                        break;
                    }
                }
                if (isset($pos)) {
                    $cn = $row[$pos];
                }
            }
            if (empty($cn)) {
                $cn = 'binary_file.dat';
            }
        }

        return sprintf(
            '<a href="transformation_wrapper.php%s&amp;ct=application'
            . '/octet-stream&amp;cn=%s" title="%s" class="disableAjax">%s</a>',
            $options['wrapper_link'],
            urlencode($cn),
            htmlspecialchars($cn),
            htmlspecialchars($cn)
        );
    }


    /* ~~~~~~~~~~~~~~~~~~~~ Getters and Setters ~~~~~~~~~~~~~~~~~~~~ */

    /**
     * Gets the transformation name of the specific plugin
     *
     * @return string
     */
    public static function getName()
    {
        return "Download";
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,7 +69,7 @@
             '<a href="transformation_wrapper.php%s&amp;ct=application'
             . '/octet-stream&amp;cn=%s" title="%s" class="disableAjax">%s</a>',
             $options['wrapper_link'],
-            urlencode($cn),
+            htmlspecialchars(urlencode($cn)),
             htmlspecialchars($cn),
             htmlspecialchars($cn)
         );
```
