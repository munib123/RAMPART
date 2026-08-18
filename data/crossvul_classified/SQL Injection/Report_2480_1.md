# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2480_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2480_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-30 of the vulnerable file.

<?php
/**
 * TestLink Open Source Project - http://testlink.sourceforge.net/
 * This script is distributed under the GNU General Public License 2 or later.
 * 
 *
 * @filesource  planUrgency.php
 * @package     TestLink
 * @author      Martin Havlat
 * @copyright   2003-2014, TestLink community 
 * @link        http://www.testlink.org
 * 
 * @internal revisions
 * @since 1.9.13
 **/
 
require('../../config.inc.php');
require_once('common.php');
testlinkInitPage($db,false,false,"checkRights");
$args = init_args();

if($args->show_help)
{
  show_instructions('test_urgency');
  exit();  
}
$templateCfg = templateConfiguration();
$tplan_mgr = new testPlanUrgency($db);
$gui = initializeGui($args,$tplan_mgr->tree_manager);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,11 +7,9 @@
  * @filesource  planUrgency.php
  * @package     TestLink
  * @author      Martin Havlat
- * @copyright   2003-2014, TestLink community 
+ * @copyright   2003-2020, TestLink community 
  * @link        http://www.testlink.org
  * 
- * @internal revisions
- * @since 1.9.13
  **/
  
 require('../../config.inc.php');
@@ -19,17 +17,16 @@
 testlinkInitPage($db,false,false,"checkRights");
 $args = init_args();
 
-if($args->show_help)
-{
+if ($args->show_help) {
   show_instructions('test_urgency');
   exit();  
 }
+
 $templateCfg = templateConfiguration();
 $tplan_mgr = new testPlanUrgency($db);
 $gui = initializeGui($args,$tplan_mgr->tree_manager);
 
-if( $args->urgency != OFF || isset($args->urgency_tc) )
-{
+if ($args->urgency != OFF || isset($args->urgency_tc)){
   $gui->user_feedback = doProcess($args,$tplan_mgr);
 }  
 
@@ -80,26 +77,18 @@
 
   // Sets urgency for suite
  
-  if (isset($_REQUEST['high_urgency']))
-  {  
+  if (isset($_REQUEST['high_urgency'])) {  
     $args->urgency = HIGH;
-  }
-  elseif (isset($_REQUEST['medium_urgency']))
-  {  
+  } elseif (isset($_REQUEST['medium_urgency'])) {  
     $args->urgency = MEDIUM;
-  }
-  elseif (isset($_REQUEST['low_urgency']))
-  {  
+  } elseif (isset($_REQUEST['low_urgency'])) {  
     $args->urgency = LOW;
-  }
-  else
-  {
+  } else {
     $args->urgency = OFF;
   }  
 
   // Sets urgency for every single tc
-  if (isset($_REQUEST['urgency'])) 
-  {
+  if (isset($_REQUEST['urgency']))  {
     $args->urgency_tc = $_REQUEST['urgency'];
   }
 
@@ -151,11 +140,10 @@
   }
 
   // Set urgency for individual testcases
-  if(isset($argsObj->urgency_tc))
-  {
-    foreach ($argsObj->urgency_tc as $id => $urgency) 
-    {
-      $tplanMgr->setTestUrgency($argsObj->tplan_id, $id, $urgency);
+  if (isset($argsObj->urgency_tc)) {
+    foreach ($argsObj->urgency_tc as $id => $urgency)  {
+      $tplanMgr->setTestUrgency($argsObj->tplan_id, 
+                                intval($id), intval($urgency));
     }
   }
 
```
