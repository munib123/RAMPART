# CrossVul Fix Pair: Inadequate Encryption Strength in php
**Pair ID:** 3158_2
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3158_2`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

 * You should have received a copy of the GNU General Public License
 *  along with sysPass.  If not, see <http://www.gnu.org/licenses/>.
 */

use SP\Core\Init;

defined('APP_ROOT') || die();

// Please, notice that this file should be outside the webserver root. You can move it and then update this path
define('XML_CONFIG_FILE', __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'config.xml');

define('BASE_DIR', __DIR__);
define('CONFIG_FILE', __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'config.php');
define('MODEL_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'SP');
define('CONTROLLER_PATH', __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'web');
define('VIEW_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'themes');
define('EXTENSIONS_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'Exts');
define('PLUGINS_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'Plugins');
define('LOCALES_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'locales');
define('SQL_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'sql');

define('DEBUG', false);

require 'SplClassLoader.php';

$ClassLoader = new SplClassLoader('SP');
$ClassLoader->setFileExtension('.class.php');
$ClassLoader->addExcluded('SP\\Profile');
$ClassLoader->addExcluded('SP\\Mgmt\\User\\Profile');
$ClassLoader->addExcluded('SP\\UserPreferences');
$ClassLoader->addExcluded('SP\\Mgmt\\User\\UserPreferences');
$ClassLoader->addExcluded('SP\\CustomFieldDef');
$ClassLoader->addExcluded('SP\\Mgmt\\CustomFieldDef');
$ClassLoader->addExcluded('SP\\PublicLink');
$ClassLoader->register();

// Empezar a calcular el tiempo y memoria utilizados
$memInit = memory_get_usage();
$timeStart = Init::microtime_float();

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,8 +38,13 @@
 define('PLUGINS_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'Plugins');
 define('LOCALES_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'locales');
 define('SQL_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'sql');
+define('LOG_FILE', __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'syspass.log');
 
 define('DEBUG', false);
+
+// Required random_compat polyfill for random_bytes() and random_int()
+// @see https://github.com/paragonie/random_compat/tree/v2.0.4#random_compat
+require_once EXTENSIONS_PATH . DIRECTORY_SEPARATOR . 'random_compat' . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . 'random.php';
 
 require 'SplClassLoader.php';
 
@@ -66,7 +71,9 @@
  */
 function debugLog($data, $printLastCaller = false)
 {
-    error_log(print_r($data, true));
+    if (!error_log(date('Y-m-d H:i:s') . ' - ' . print_r($data, true) . PHP_EOL, 3, LOG_FILE)) {
+        error_log(print_r($data, true));
+    }
 
     if ($printLastCaller === true) {
         $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
@@ -74,7 +81,11 @@
 
         for ($i = 1; $i <= $n - 1; $i++) {
             $class = isset($backtrace[$i]['class']) ? $backtrace[$i]['class'] : '';
-            error_log(sprintf('Caller %d: %s\%s', $i, $class, $backtrace[$i]['function']));
+            $line = sprintf('Caller %d: %s\%s', $i, $class, $backtrace[$i]['function']);
+
+            if (!error_log($line . PHP_EOL, 3, LOG_FILE)) {
+                error_log($line);
+            }
         }
     }
 }
@@ -83,7 +94,7 @@
  * Alias gettext function
  *
  * @param string $string
- * @param bool   $tranlate Si es necesario traducir
+ * @param bool $tranlate Si es necesario traducir
  * @return string
  */
 function __($string, $tranlate = true)
```
