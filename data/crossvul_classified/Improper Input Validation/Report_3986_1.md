# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3986_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3986_1`)

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
 * Custom Fields definition import management
 *
 * @package 	  TestLink
 * @author 		  Francisco Mancardi (francisco.mancardi@gmail.com)
 * @copyright 	2005-2013, TestLink community 
 * @filesource  cfieldsImport.php,v 1.5 2010/03/15 20:22:42 franciscom Exp $
 * @link 		    http://www.teamst.org/index.php
 * @uses 		    config.inc.php
 *
 * @internal revisions
 * @since 1.9.9
 */
require('../../config.inc.php');
require_once('common.php');
require_once('xml.inc.php');

testlinkInitPage($db,false,false,"checkRights");
$templateCfg = templateConfiguration();

$resultMap = null;
$args = init_args();

$gui=new stdClass();
$gui->page_title=lang_get('import_cfields');
$gui->goback_url = !is_null($args->goback_url) ? $args->goback_url : ''; 
$gui->file_check = array('show_results' => 0, 'status_ok' => 1, 
                         'msg' => 'ok', 'filename' => '');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,13 +7,10 @@
  *
  * @package 	  TestLink
  * @author 		  Francisco Mancardi (francisco.mancardi@gmail.com)
- * @copyright 	2005-2013, TestLink community 
- * @filesource  cfieldsImport.php,v 1.5 2010/03/15 20:22:42 franciscom Exp $
- * @link 		    http://www.teamst.org/index.php
+ * @copyright 	2005-2020, TestLink community 
+ * @filesource  cfieldsImport.php
  * @uses 		    config.inc.php
  *
- * @internal revisions
- * @since 1.9.9
  */
 require('../../config.inc.php');
 require_once('common.php');
@@ -64,17 +61,16 @@
 	$args = new stdClass();
 	$_REQUEST = strings_stripSlashes($_REQUEST);
 
-	$iParams = array("doAction" => array(tlInputParameter::STRING_N,0,50),
-	 				 "export_filename" => array(tlInputParameter::STRING_N,0,100),
-	 				 "goback_url" => array(tlInputParameter::STRING_N,0,2048));
+	$iParams = 
+    array("doAction" => array(tlInputParameter::STRING_N,0,50),
+	 				"export_filename" 
+             => array(tlInputParameter::STRING_N,0,100));
 
 	R_PARAMS($iParams,$args);
+  $args->userID = $_SESSION['userID'];
 
-  	// $args->doAction = isset($_REQUEST['doAction']) ? $_REQUEST['doAction'] : null;
-  	// $args->export_filename=isset($_REQUEST['export_filename']) ? $_REQUEST['export_filename'] : null;
-  	// $args->goback_url = isset($_REQUEST['goback_url']) ? $_REQUEST['goback_url'] : null;
-
-  	$args->userID = $_SESSION['userID'];
+  $args->goback_url = $_SESSION['basehref'] .
+                      'lib/cfields/cfieldsView.php';
 
 	return $args;
 }
```
