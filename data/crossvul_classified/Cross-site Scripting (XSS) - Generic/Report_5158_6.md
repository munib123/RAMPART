# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5158_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5158_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 54-89 of the vulnerable file.

                $buffer,
                $options[0],
                $options[1]
            );
        } else {
            $newtext = mb_substr($buffer, $options[0]);
        }

        $length = mb_strlen($newtext);
        $baselength = mb_strlen($buffer);
        if ($length != $baselength) {
            if ($options[0] != 0) {
                $newtext = $options[2] . $newtext;
            }

            if (($length + $options[0]) != $baselength) {
                $newtext .= $options[2];
            }
        }

        return $newtext;
    }


    /* ~~~~~~~~~~~~~~~~~~~~ Getters and Setters ~~~~~~~~~~~~~~~~~~~~ */

    /**
     * Gets the transformation name of the specific plugin
     *
     * @return string
     */
    public static function getName()
    {
        return "Substring";
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,7 +71,7 @@
             }
         }
 
-        return $newtext;
+        return htmlspecialchars($newtext);
     }
 
 
```
