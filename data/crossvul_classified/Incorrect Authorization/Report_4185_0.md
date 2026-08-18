# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4185_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4185_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 1-12 of the vulnerable file.

<?php namespace October\Rain\Exception;

/**
 * This class represents a critical system exception.
 * System exceptions are logged in the error log.
 *
 * @package october\exception
 * @author Alexey Bobkov, Samuel Georges
 */
class SystemException extends ExceptionBase
{
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,12 +1,29 @@
 <?php namespace October\Rain\Exception;
+
+use Exception;
+use October\Rain\Html\HtmlBuilder;
 
 /**
  * This class represents a critical system exception.
  * System exceptions are logged in the error log.
  *
  * @package october\exception
- * @author Alexey Bobkov, Samuel Georges
+ * @author Alexey Bobkov, Samuel Georges, Luke Towers
  */
 class SystemException extends ExceptionBase
 {
+    /**
+     * Override the constructor to escape all messages to protect against potential XSS
+     * from user provided inputs being included in the exception message
+     *
+     * @param string $message Error message.
+     * @param int $code Error code.
+     * @param Exception $previous Previous exception.
+     */
+    public function __construct($message = "", $code = 0, Exception $previous = null)
+    {
+        $message = HtmlBuilder::clean($message);
+
+        parent::__construct($message, $code, $previous);
+    }
 }
```
