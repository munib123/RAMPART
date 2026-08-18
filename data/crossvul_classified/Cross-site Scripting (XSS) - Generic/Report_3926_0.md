# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3926_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3926_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 18-58 of the vulnerable file.

 * GLPI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GLPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GLPI. If not, see <http://www.gnu.org/licenses/>.
 * ---------------------------------------------------------------------
 */

// Include plugin if it is a plugin table
if (!strstr($_GET['itemtype'], "Plugin")) {
   $AJAX_INCLUDE = 1;
}
include ('../inc/includes.php');
header("Content-Type: text/html; charset=UTF-8");
Html::header_nocache();

Session::checkLoginUser();

// Security
if (!isset($_GET['itemtype']) || !($item = getItemForItemtype($_GET['itemtype']))) {
   exit();
}

$item->getEmpty();
$table = $item->getTable();
// Security
if (!isset($item->fields[$_GET['field']]) || !$item->canView()) {
   exit();
}

// Security : check whitelist
$field_so = $item->getSearchOptionByField('field', $_GET['field'], $item->getTable());
$can_autocomplete = array_key_exists('autocomplete', $field_so) && $field_so['autocomplete'];
if (!$can_autocomplete) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,7 +35,7 @@
    $AJAX_INCLUDE = 1;
 }
 include ('../inc/includes.php');
-header("Content-Type: text/html; charset=UTF-8");
+header("Content-Type: application/json; charset=UTF-8");
 Html::header_nocache();
 
 Session::checkLoginUser();
```
