# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5146_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5146_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 622-662 of the vulnerable file.

                        continue;
                    }
                }

                // user preferences allow/disallow
                if ($is_setup_script
                    && isset($this->_userprefsKeys[$system_path])
                ) {
                    if (isset($this->_userprefsDisallow[$system_path])
                        && isset($_POST[$key . '-userprefs-allow'])
                    ) {
                        unset($this->_userprefsDisallow[$system_path]);
                    } else if (!isset($_POST[$key . '-userprefs-allow'])) {
                        $this->_userprefsDisallow[$system_path] = true;
                    }
                }

                // cast variables to correct type
                switch ($type) {
                case 'double':
                    settype($_POST[$key], 'float');
                    break;
                case 'boolean':
                case 'integer':
                    if ($_POST[$key] !== '') {
                        settype($_POST[$key], $type);
                    }
                    break;
                case 'select':
                    $successfully_validated = $this->_validateSelect(
                        $_POST[$key],
                        $form->getOptionValueList($system_path)
                    );
                    if (! $successfully_validated) {
                        $this->_errors[$work_path][] = __('Incorrect value!');
                        $result = false;
                        continue;
                    }
                    break;
                case 'string':
                case 'short_string':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -639,12 +639,12 @@
                 // cast variables to correct type
                 switch ($type) {
                 case 'double':
-                    settype($_POST[$key], 'float');
+                    settype($this->_trimString($_POST[$key]), 'float');
                     break;
                 case 'boolean':
                 case 'integer':
                     if ($_POST[$key] !== '') {
-                        settype($_POST[$key], $type);
+                        settype($this->_trimString($_POST[$key]), $type);
                     }
                     break;
                 case 'select':
@@ -660,7 +660,7 @@
                     break;
                 case 'string':
                 case 'short_string':
-                    $_POST[$key] = trim($_POST[$key]);
+                    $_POST[$key] = $this->_trimString($_POST[$key]);
                     break;
                 case 'array':
                     // eliminate empty values and ensure we have an array
@@ -876,10 +876,25 @@
     private function _fillPostArrayParameters($post_values, $key)
     {
         foreach ($post_values as $v) {
-            $v = trim($v);
+            $v = $this->_trimString($v);
             if ($v !== '') {
                 $_POST[$key][] = $v;
             }
         }
     }
+
+    /*
+     * Converts given (request) paramter to string
+     *
+     * @param mixed $value Value to convert
+     *
+     * @return string
+     */
+    private function _trimString($value)
+    {
+        while (is_array($value)) {
+            $value = reset($value);
+        }
+        return trim((string)$value);
+    }
 }
```
