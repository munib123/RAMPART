# CrossVul Fix Pair: Generation of Error Message Containing Sensitive Information in php
**Pair ID:** 2464_0
**Vulnerability Class:** Information Exposure Through an Error Message
**CWE:** CWE-209
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2464_0`)

## Vulnerability Information & PoC

## Description
Generation of Error Message Containing Sensitive Information - The sensitive information may be valuable information on its own (such as a password), or it may be useful for launching other, more serious attacks.

## Vulnerable Code
```php
Lines 14-36 of the vulnerable file.

/**
 * Registers all the debug tools.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class Debug
{
    public static function enable(): ErrorHandler
    {
        error_reporting(-1);

        if (!\in_array(\PHP_SAPI, ['cli', 'phpdbg'], true)) {
            ini_set('display_errors', 0);
        } elseif (!filter_var(ini_get('log_errors'), FILTER_VALIDATE_BOOLEAN) || ini_get('error_log')) {
            // CLI - display errors only if they're not already logged to STDERR
            ini_set('display_errors', 1);
        }

        DebugClassLoader::enable();

        return ErrorHandler::register(new ErrorHandler(new BufferingLogger()));
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,6 @@
 
         DebugClassLoader::enable();
 
-        return ErrorHandler::register(new ErrorHandler(new BufferingLogger()));
+        return ErrorHandler::register(new ErrorHandler(new BufferingLogger(), true));
     }
 }
```
