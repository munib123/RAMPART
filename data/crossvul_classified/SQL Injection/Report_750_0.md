# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 750_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `750_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.

 * along with GLPI. If not, see <http://www.gnu.org/licenses/>.
 * ---------------------------------------------------------------------
 */

// Ensure current directory when run from crontab
chdir(__DIR__);

use Glpi\Event;

include ('../inc/includes.php');

if (isset($_SERVER['argv'])) {
   for ($i=1; $i<$_SERVER['argc']; $i++) {
      $it    = explode("=", $_SERVER['argv'][$i], 2);
      $it[0] = preg_replace('/^--/', '', $it[0]);

      $_GET[$it[0]] = (isset($it[1]) ? $it[1] : true);
   }
}
if (isset($_GET['cycle'])) {
   $cycle = $_GET['cycle'];
} else {
   $cycle = 25;
}

if (isset($_GET['only_tasks'])) {
   $only_tasks = explode(',', $_GET['only_tasks']);
} else {
   $only_tasks = [];
}

$crontask = new Crontask();
$query    = "SELECT `id`, `name`
             FROM `glpi_crontasks`
             WHERE `state` = '".Crontask::STATE_RUNNING."'
                   AND unix_timestamp(`lastrun`) + $cycle * `frequency` < unix_timestamp(now())";

//Number of unlocked tasks by the script
$unlocked_tasks = 0;

echo "Date : ".Html::convDateTime($_SESSION['glpi_currenttime'])."\n";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,7 @@
    }
 }
 if (isset($_GET['cycle'])) {
-   $cycle = $_GET['cycle'];
+   $cycle = (int)$_GET['cycle'];
 } else {
    $cycle = 25;
 }
```
