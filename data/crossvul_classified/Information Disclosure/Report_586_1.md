# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 586_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `586_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 307-346 of the vulnerable file.


    /**
     * Converts an exception into a PHP error.
     *
     * This method can be used to convert exceptions inside of methods like `__toString()`
     * to PHP errors because exceptions cannot be thrown inside of them.
     * @param \Exception $exception the exception to convert to a PHP error.
     */
    public static function convertExceptionToError($exception)
    {
        trigger_error(static::convertExceptionToString($exception), E_USER_ERROR);
    }

    /**
     * Converts an exception into a simple string.
     * @param \Exception|\Error $exception the exception being converted
     * @return string the string representation of the exception.
     */
    public static function convertExceptionToString($exception)
    {
        if ($exception instanceof Exception && ($exception instanceof UserException || !YII_DEBUG)) {
            $message = "{$exception->getName()}: {$exception->getMessage()}";
        } elseif (YII_DEBUG) {
            if ($exception instanceof Exception) {
                $message = "Exception ({$exception->getName()})";
            } elseif ($exception instanceof ErrorException) {
                $message = "{$exception->getName()}";
            } else {
                $message = 'Exception';
            }
            $message .= " '" . get_class($exception) . "' with message '{$exception->getMessage()}' \n\nin "
                . $exception->getFile() . ':' . $exception->getLine() . "\n\n"
                . "Stack trace:\n" . $exception->getTraceAsString();
        } else {
            $message = 'Error: ' . $exception->getMessage();
        }

        return $message;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -324,22 +324,36 @@
      */
     public static function convertExceptionToString($exception)
     {
-        if ($exception instanceof Exception && ($exception instanceof UserException || !YII_DEBUG)) {
-            $message = "{$exception->getName()}: {$exception->getMessage()}";
-        } elseif (YII_DEBUG) {
-            if ($exception instanceof Exception) {
-                $message = "Exception ({$exception->getName()})";
-            } elseif ($exception instanceof ErrorException) {
-                $message = "{$exception->getName()}";
-            } else {
-                $message = 'Exception';
-            }
-            $message .= " '" . get_class($exception) . "' with message '{$exception->getMessage()}' \n\nin "
-                . $exception->getFile() . ':' . $exception->getLine() . "\n\n"
-                . "Stack trace:\n" . $exception->getTraceAsString();
+        if ($exception instanceof UserException) {
+            return "{$exception->getName()}: {$exception->getMessage()}";
+        }
+
+        if (YII_DEBUG) {
+            return static::convertExceptionToVerboseString($exception);
+        }
+
+        return 'An internal server error occurred.';
+    }
+
+    /**
+     * Converts an exception into a string that has verbose information about the exception and its trace.
+     * @param \Exception|\Error $exception the exception being converted
+     * @return string the string representation of the exception.
+     *
+     * @since 2.0.14
+     */
+    public static function convertExceptionToVerboseString($exception)
+    {
+        if ($exception instanceof Exception) {
+            $message = "Exception ({$exception->getName()})";
+        } elseif ($exception instanceof ErrorException) {
+            $message = "{$exception->getName()}";
         } else {
-            $message = 'Error: ' . $exception->getMessage();
-        }
+            $message = 'Exception';
+        }
+        $message .= " '" . get_class($exception) . "' with message '{$exception->getMessage()}' \n\nin "
+            . $exception->getFile() . ':' . $exception->getLine() . "\n\n"
+            . "Stack trace:\n" . $exception->getTraceAsString();
 
         return $message;
     }
```
