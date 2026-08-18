# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3986_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3986_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
/**
 * TestLink Open Source Project - http://testlink.sourceforge.net/ 
 * This script is distributed under the GNU General Public License 2 or later.
 *  
 * Custom Fields definition export management
 *
 * @package   TestLink
 * @author    Francisco Mancardi (francisco.mancardi@gmail.com)
 * @copyright   2005-2009, TestLink community 
 * @version     CVS: $Id: cfieldsExport.php,v 1.4 2010/03/15 20:23:09 franciscom Exp $
 * @link    http://www.teamst.org/index.php
 * @uses    config.inc.php
 *
 * @internal Revisions:
 * 20100315 - franciscom - added tlInputParameter() on init_args + goback managament
 * 20090719 - franciscom - db table prefix management   
 *
 */
require_once("../../config.inc.php");
require_once("common.php");
require_once('../../third_party/adodb_xml/class.ADODB_XML.php');

testlinkInitPage($db,false,false,"checkRights");
$templateCfg = templateConfiguration();
$args = init_args();

$gui = new stdClass();
$gui->page_title = lang_get('export_cfields');
$gui->do_it = 1;
$gui->nothing_todo_msg = '';
$gui->goback_url = !is_null($args->goback_url) ? $args->goback_url : ''; 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,14 +7,9 @@
  *
  * @package   TestLink
  * @author    Francisco Mancardi (francisco.mancardi@gmail.com)
- * @copyright   2005-2009, TestLink community 
- * @version     CVS: $Id: cfieldsExport.php,v 1.4 2010/03/15 20:23:09 franciscom Exp $
- * @link    http://www.teamst.org/index.php
+ * @copyright   2005-2020, TestLink community 
  * @uses    config.inc.php
  *
- * @internal Revisions:
- * 20100315 - franciscom - added tlInputParameter() on init_args + goback managament
- * 20090719 - franciscom - db table prefix management   
  *
  */
 require_once("../../config.inc.php");
@@ -24,6 +19,7 @@
 testlinkInitPage($db,false,false,"checkRights");
 $templateCfg = templateConfiguration();
 $args = init_args();
+
 
 $gui = new stdClass();
 $gui->page_title = lang_get('export_cfields');
@@ -61,12 +57,17 @@
   $args = new stdClass();
   $_REQUEST = strings_stripSlashes($_REQUEST);
 
-  $iParams = array("doAction" => array(tlInputParameter::STRING_N,0,50),
-           "export_filename" => array(tlInputParameter::STRING_N,0,100),
-           "goback_url" => array(tlInputParameter::STRING_N,0,2048));
+  $iParams = 
+    array("doAction" 
+             => array(tlInputParameter::STRING_N,0,50),
+           "export_filename" 
+              => array(tlInputParameter::STRING_N,0,100));
 
   R_PARAMS($iParams,$args);
-    $args->userID = $_SESSION['userID'];
+  $args->userID = $_SESSION['userID'];
+
+  $args->goback_url = $_SESSION['basehref'] .
+                      'lib/cfields/cfieldsView.php';
 
   return $args;
 }
```
