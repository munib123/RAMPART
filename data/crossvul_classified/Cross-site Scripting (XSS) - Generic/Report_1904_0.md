# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1904_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1904_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.

 * along with GLPI. If not, see <http://www.gnu.org/licenses/>.
 * ---------------------------------------------------------------------
 */

use Glpi\Features\Kanban;

$AJAX_INCLUDE = 1;

include ('../inc/includes.php');

header("Content-Type: text/html; charset=UTF-8");
Html::header_nocache();

Session::checkLoginUser();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
   // Get AJAX input and load it into $_REQUEST
   $input = file_get_contents('php://input');
   parse_str($input, $_REQUEST);
}

if (!isset($_REQUEST['action'])) {
   Toolbox::logError("Missing action parameter");
   http_response_code(400);
   return;
}
$action = $_REQUEST['action'];

$nonkanban_actions = ['update', 'bulk_add_item', 'add_item', 'move_item'];
if (isset($_REQUEST['itemtype'])) {
   $traits = class_uses($_REQUEST['itemtype'], true);
   if (!in_array($_REQUEST['action'], $nonkanban_actions) && (!$traits || !in_array(Kanban::class, $traits, true))) {
      // Bad request
      // For all actions, except those in $nonkanban_actions, we expect to be manipulating the Kanban itself.
      Toolbox::logError("Invalid itemtype parameter");
      http_response_code(400);
      return;
   }
   /** @var CommonDBTM $item */
   $itemtype = $_REQUEST['itemtype'];
   $item = new $itemtype();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,6 +46,8 @@
    $input = file_get_contents('php://input');
    parse_str($input, $_REQUEST);
 }
+
+$_REQUEST = Toolbox::clean_cross_side_scripting_deep($_REQUEST);
 
 if (!isset($_REQUEST['action'])) {
    Toolbox::logError("Missing action parameter");
```
