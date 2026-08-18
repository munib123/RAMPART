# CrossVul Fix Pair: Data Processing Errors in php
**Pair ID:** 757_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `757_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```php
Lines 33-62 of the vulnerable file.

 * This file is used to send the inventory to user browser.
 *
 * ------------------------------------------------------------------------
 *
 * @package   FusionInventory
 * @author    Vincent Mazzoni
 * @author    David Durieux
 * @copyright Copyright (c) 2010-2016 FusionInventory team
 * @license   AGPL License 3.0 or (at your option) any later version
 *            http://www.gnu.org/licenses/agpl-3.0-standalone.html
 * @link      http://www.fusioninventory.org/
 * @link      https://github.com/fusioninventory/fusioninventory-for-glpi
 *
 */

include ("../../../inc/includes.php");

//Session::checkRight('config', "w");

$itemtype = $_GET['itemtype'];
$function = $_GET['function'];
$items_id = $_GET['items_id'];

header('Cache-control: private, must-revalidate'); /// IE BUG + SSL
header('Content-disposition: attachment; filename='.$_GET['filename']);
header('Content-type: text/plain');


call_user_func(['PluginFusioninventoryToolbox', $function], $items_id, $itemtype);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,7 +50,6 @@
 //Session::checkRight('config', "w");
 
 $itemtype = $_GET['itemtype'];
-$function = $_GET['function'];
 $items_id = $_GET['items_id'];
 
 header('Cache-control: private, must-revalidate'); /// IE BUG + SSL
@@ -58,5 +57,5 @@
 header('Content-type: text/plain');
 
 
-call_user_func(['PluginFusioninventoryToolbox', $function], $items_id, $itemtype);
+call_user_func(['PluginFusioninventoryToolbox', 'sendXML'], $items_id, $itemtype);
 
```
