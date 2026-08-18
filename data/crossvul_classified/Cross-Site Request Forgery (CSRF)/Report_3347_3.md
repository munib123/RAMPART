# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3347_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3347_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 4-40 of the vulnerable file.


namespace Composer\Autoload;

class ComposerStaticInit873464e4bd965a3168f133248b1b218b
{
    public static $prefixLengthsPsr4 = array (
        'R' => 
        array (
            'RobThree\\Auth\\' => 14,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'RobThree\\Auth\\' => 
        array (
            0 => __DIR__ . '/..' . '/robthree/twofactorauth/lib',
        ),
    );

    public static $classMap = array (
        'u2flib_server\\Error' => __DIR__ . '/..' . '/yubico/u2flib-server/src/u2flib_server/U2F.php',
        'u2flib_server\\RegisterRequest' => __DIR__ . '/..' . '/yubico/u2flib-server/src/u2flib_server/U2F.php',
        'u2flib_server\\Registration' => __DIR__ . '/..' . '/yubico/u2flib-server/src/u2flib_server/U2F.php',
        'u2flib_server\\SignRequest' => __DIR__ . '/..' . '/yubico/u2flib-server/src/u2flib_server/U2F.php',
        'u2flib_server\\U2F' => __DIR__ . '/..' . '/yubico/u2flib-server/src/u2flib_server/U2F.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit873464e4bd965a3168f133248b1b218b::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit873464e4bd965a3168f133248b1b218b::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit873464e4bd965a3168f133248b1b218b::$classMap;

        }, null, ClassLoader::class);
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,14 @@
     );
 
     public static $classMap = array (
+        'alreadyInitializedException' => __DIR__ . '/..' . '/owasp/csrf-protector-php/libs/csrf/csrfprotector.php',
+        'baseJSFileNotFoundExceptio' => __DIR__ . '/..' . '/owasp/csrf-protector-php/libs/csrf/csrfprotector.php',
+        'configFileNotFoundException' => __DIR__ . '/..' . '/owasp/csrf-protector-php/libs/csrf/csrfprotector.php',
+        'csrfProtector' => __DIR__ . '/..' . '/owasp/csrf-protector-php/libs/csrf/csrfprotector.php',
+        'incompleteConfigurationException' => __DIR__ . '/..' . '/owasp/csrf-protector-php/libs/csrf/csrfprotector.php',
+        'jsFileNotFoundException' => __DIR__ . '/..' . '/owasp/csrf-protector-php/libs/csrf/csrfprotector.php',
+        'logDirectoryNotFoundException' => __DIR__ . '/..' . '/owasp/csrf-protector-php/libs/csrf/csrfprotector.php',
+        'logFileWriteError' => __DIR__ . '/..' . '/owasp/csrf-protector-php/libs/csrf/csrfprotector.php',
         'u2flib_server\\Error' => __DIR__ . '/..' . '/yubico/u2flib-server/src/u2flib_server/U2F.php',
         'u2flib_server\\RegisterRequest' => __DIR__ . '/..' . '/yubico/u2flib-server/src/u2flib_server/U2F.php',
         'u2flib_server\\Registration' => __DIR__ . '/..' . '/yubico/u2flib-server/src/u2flib_server/U2F.php',
```
