# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2122_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2122_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 180-220 of the vulnerable file.


/**
 * Utility function to return a value from a named array or a specified
 *  default, and avoid poisoning the URL by denying:
 * 1) the use of spaces (for SQL and XSS injection)
 * 2) the use of <, ", [, ; and { (for XSS injection)
 */
function w2PgetParam(&$arr, $name, $def = null)
{
    $key = preg_replace("/[^A-Za-z0-9_]/", "", $name);

    if (isset($arr[$key])) {
        if (is_array($arr[$key])) {
            $_result = $arr[$key];
            foreach($_result as $_key => $_value) {
                $_result[$_key] = preg_replace("/<>'\"\[\]{}:;/", "", $_value);
            }
            $result  = $_result;
        } else {
            $_result = strip_tags($arr[$key]);
            $result  = preg_replace("/<>'\"\[\]{}:;/", "", $_result);
        }
    } else {
        $result = $def;
    }

    return $result;
}

function convert2days($durn, $units)
{
    switch ($units) {
        case 0:
        case 1:
            return $durn / w2PgetConfig('daily_working_hours');
            break;
        case 24:
            return $durn;
    }
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -197,7 +197,7 @@
             $result  = $_result;
         } else {
             $_result = strip_tags($arr[$key]);
-            $result  = preg_replace("/<>'\"\[\]{}:;/", "", $_result);
+            $result  = preg_replace("/<>\`'\"\[\]{}():;/", "", $_result);
         }
     } else {
         $result = $def;
```
