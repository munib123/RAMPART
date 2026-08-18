# CrossVul Fix Pair: Generation of Error Message Containing Sensitive Information in php
**Pair ID:** 2464_1
**Vulnerability Class:** Information Exposure Through an Error Message
**CWE:** CWE-209
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2464_1`)

## Vulnerability Information & PoC

## Description
Generation of Error Message Containing Sensitive Information - The sensitive information may be valuable information on its own (such as a password), or it may be useful for launching other, more serious attacks.

## Vulnerable Code
```php
Lines 75-115 of the vulnerable file.

        E_USER_NOTICE => [null, LogLevel::WARNING],
        E_STRICT => [null, LogLevel::WARNING],
        E_WARNING => [null, LogLevel::WARNING],
        E_USER_WARNING => [null, LogLevel::WARNING],
        E_COMPILE_WARNING => [null, LogLevel::WARNING],
        E_CORE_WARNING => [null, LogLevel::WARNING],
        E_USER_ERROR => [null, LogLevel::CRITICAL],
        E_RECOVERABLE_ERROR => [null, LogLevel::CRITICAL],
        E_COMPILE_ERROR => [null, LogLevel::CRITICAL],
        E_PARSE => [null, LogLevel::CRITICAL],
        E_ERROR => [null, LogLevel::CRITICAL],
        E_CORE_ERROR => [null, LogLevel::CRITICAL],
    ];

    private $thrownErrors = 0x1FFF; // E_ALL - E_DEPRECATED - E_USER_DEPRECATED
    private $scopedErrors = 0x1FFF; // E_ALL - E_DEPRECATED - E_USER_DEPRECATED
    private $tracedErrors = 0x77FB; // E_ALL - E_STRICT - E_PARSE
    private $screamedErrors = 0x55; // E_ERROR + E_CORE_ERROR + E_COMPILE_ERROR + E_PARSE
    private $loggedErrors = 0;
    private $traceReflector;

    private $isRecursive = 0;
    private $isRoot = false;
    private $exceptionHandler;
    private $bootstrappingLogger;

    private static $reservedMemory;
    private static $toStringException;
    private static $silencedErrorCache = [];
    private static $silencedErrorCount = 0;
    private static $exitCode = 0;

    /**
     * Registers the error handler.
     */
    public static function register(self $handler = null, bool $replace = true): self
    {
        if (null === self::$reservedMemory) {
            self::$reservedMemory = str_repeat('x', 10240);
            register_shutdown_function(__CLASS__.'::handleFatalError');
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,6 +92,7 @@
     private $screamedErrors = 0x55; // E_ERROR + E_CORE_ERROR + E_COMPILE_ERROR + E_PARSE
     private $loggedErrors = 0;
     private $traceReflector;
+    private $debug;
 
     private $isRecursive = 0;
     private $isRoot = false;
@@ -180,7 +181,7 @@
         }
     }
 
-    public function __construct(BufferingLogger $bootstrappingLogger = null)
+    public function __construct(BufferingLogger $bootstrappingLogger = null, bool $debug = false)
     {
         if ($bootstrappingLogger) {
             $this->bootstrappingLogger = $bootstrappingLogger;
@@ -188,6 +189,7 @@
         }
         $this->traceReflector = new \ReflectionProperty('Exception', 'trace');
         $this->traceReflector->setAccessible(true);
+        $this->debug = $debug;
     }
 
     /**
@@ -697,7 +699,7 @@
      */
     private function renderException(\Throwable $exception): void
     {
-        $renderer = \in_array(\PHP_SAPI, ['cli', 'phpdbg'], true) ? new CliErrorRenderer() : new HtmlErrorRenderer(0 !== $this->scopedErrors);
+        $renderer = \in_array(\PHP_SAPI, ['cli', 'phpdbg'], true) ? new CliErrorRenderer() : new HtmlErrorRenderer($this->debug);
 
         $exception = $renderer->render($exception);
 
```
