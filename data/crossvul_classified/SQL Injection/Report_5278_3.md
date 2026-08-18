# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5278_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5278_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 505-561 of the vulnerable file.

        if (is_array($data)) {
            $saved_params = array();
            if (!empty($data['controller']) && $data['controller'] == 'snippet') {
                $saved_params['body'] = $data['body'];  // store snippet body
            }
            foreach ($data as $var=>$val) {
//                $data[$var] = self::sanitize($val);
                $data[$var] = self::xss_clean($val);
            }
            if (!empty($saved_params)) {
                $data = array_merge($data, $saved_params);  // add stored snippet body
            }
        } else {
            if (empty($data)) {
                return $data;
            }

            $data = self::xss_clean($data);

            //fixme orig exp method
            if(0) {
                // remove whitespaces and tags
//            $data = strip_tags(trim($data));
                // remove whitespaces and script tags
                $data = self::strip_tags_content(trim($data), '<script>', true);
//            $data = self::strip_tags_content(trim($data), '<iframe>', true);

                // apply stripslashes if magic_quotes_gpc is enabled
                if (get_magic_quotes_gpc()) {
                    $data = stripslashes($data);
                }

                $data = self::escape($data);

                // re-escape newlines
                $data = str_replace(array('\r', '\n'), array("\r", "\n"), $data);
            }
        }
        return $data;
    }

    // xss_clean //

    /**
  	 * Character set
  	 *
  	 * Will be overridden by the constructor.
  	 *
  	 * @var	string
  	 */
  	public static $charset = 'UTF-8';

    /**
   	 * XSS Hash
   	 *
   	 * Random Hash for protecting URLs.
   	 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -522,23 +522,23 @@
             $data = self::xss_clean($data);
 
             //fixme orig exp method
-            if(0) {
-                // remove whitespaces and tags
-//            $data = strip_tags(trim($data));
-                // remove whitespaces and script tags
-                $data = self::strip_tags_content(trim($data), '<script>', true);
-//            $data = self::strip_tags_content(trim($data), '<iframe>', true);
-
-                // apply stripslashes if magic_quotes_gpc is enabled
-                if (get_magic_quotes_gpc()) {
-                    $data = stripslashes($data);
-                }
-
-                $data = self::escape($data);
-
-                // re-escape newlines
-                $data = str_replace(array('\r', '\n'), array("\r", "\n"), $data);
-            }
+//            if(0) {
+//                // remove whitespaces and tags
+////            $data = strip_tags(trim($data));
+//                // remove whitespaces and script tags
+//                $data = self::strip_tags_content(trim($data), '<script>', true);
+////            $data = self::strip_tags_content(trim($data), '<iframe>', true);
+//
+//                // apply stripslashes if magic_quotes_gpc is enabled
+//                if (get_magic_quotes_gpc()) {
+//                    $data = stripslashes($data);
+//                }
+//
+//                $data = self::escape($data);
+//
+//                // re-escape newlines
+//                $data = str_replace(array('\r', '\n'), array("\r", "\n"), $data);
+//            }
         }
         return $data;
     }
```
