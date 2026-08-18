# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 2176_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2176_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
require_once('sources/sessions.php');
session_start();
@openlog("TeamPass", LOG_PID | LOG_PERROR, LOG_LOCAL0);

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<?php
/**
 *
 * @file          index.php
 * @author        Nils Laumaillé
 * @version       2.1.19
 * @copyright     (c) 2009-2014 Nils Laumaillé
 * @licensing     GNU AFFERO GPL 3.0
 * @link          http://www.teampass.net
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

$_SESSION['CPM'] = 1;
session_id();

// Test if settings.file exists, if not then install
if (!file_exists('includes/settings.php')) {
    echo '
    <script language="javascript" type="text/javascript">
    <!--
    document.location.replace("install/install.php");
    clearInterval(timer);
    -->
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,7 @@
  *
  * @file          index.php
  * @author        Nils Laumaillé
- * @version       2.1.19
+ * @version       2.1.20
  * @copyright     (c) 2009-2014 Nils Laumaillé
  * @licensing     GNU AFFERO GPL 3.0
  * @link          http://www.teampass.net
@@ -51,15 +51,12 @@
 
 //load main functions needed
 require_once 'sources/main.functions.php';
+// Load CORE
+require_once $_SESSION['settings']['cpassman_dir'].'/sources/core.php';
 
 /* DEFINE WHAT LANGUAGE TO USE */
 if (!isset($_SESSION['user_id']) && !isset($_POST['language'])) {
     //get default language
-    /*$dataLanguage =
-        $db->fetchRow(
-            "SELECT valeur FROM ".$pre."misc
-            WHERE type = 'admin' AND intitule = 'default_language'"
-        );*/
     $dataLanguage = $db->queryGetRow(
         "misc",
         array(
@@ -91,12 +88,16 @@
     }
 }
 // Load user languages files
-require_once $_SESSION['settings']['cpassman_dir'].'/includes/language/'.$_SESSION['user_language'].'.php';
-if (isset($_GET['page']) && $_GET['page'] == "kb") {
-    require_once $_SESSION['settings']['cpassman_dir'].'/includes/language/'.$_SESSION['user_language'].'_kb.php';
-}
-// Load CORE
-require_once $_SESSION['settings']['cpassman_dir'].'/sources/core.php';
+if (in_array($_SESSION['user_language'], $languagesList)) {
+	require_once $_SESSION['settings']['cpassman_dir'].'/includes/language/'.$_SESSION['user_language'].'.php';
+	if (isset($_GET['page']) && $_GET['page'] == "kb") {
+		require_once $_SESSION['settings']['cpassman_dir'].'/includes/language/'.$_SESSION['user_language'].'_kb.php';
+	}
+} else {
+	$_SESSION['error']['code'] = ERR_NOT_ALLOWED; //not allowed page
+	include 'error.php';
+}
+
 // Load links, css and javascripts
 @require_once $_SESSION['settings']['cpassman_dir'].'/load.php';
 ?>
@@ -208,7 +209,8 @@
         </div>';
 }
 // Display language menu
-echo '
+if (!isset($_GET['otv'])) {
+	echo '
         <div style="float:right;">
             <dl id="flags" class="dropdown">
                 <dt><img src="includes/images/flags/'.$_SESSION['user_language_flag'].'" alt="" /></dt>
@@ -218,7 +220,9 @@
                     </ul>
                 </dd>
             </dl>
-        </div>
+        </div>';
+}
+echo '
     </div>';
 
 /* LAST SEEN */
@@ -299,7 +303,9 @@
             <br />
             <button title="'.$txt['history'].'" id="menu_button_history" class="" onclick="OpenDialog(\'div_item_history\', \'false\')"><img src="includes/images/report.png" id="div_history" alt="" /></button>
             <br />
-            <button title="'.$txt['share'].'" id="menu_button_share" class="" onclick="OpenDialog(\'div_item_share\', \'false\')"><img src="includes/images/share.png" id="div_share" alt="" /></button>';
+            <button title="'.$txt['share'].'" id="menu_button_share" class="" onclick="OpenDialog(\'div_item_share\', \'false\')"><img src="includes/images/share.png" id="div_share" alt="" /></button>
+			<br />
+            <button title="'.$txt['one_time_item_view'].'" id="menu_button_otv" class="" onclick="prepareOneTimeView()"><img src="includes/images/globe-share.png" id="div_otv" alt="" /></button>';
     if (isset($_SESSION['settings']['enable_email_notification_on_item_shown']) && $_SESSION['settings']['enable_email_notification_on_item_shown'] == 1) {
         echo '
             <br />
@@ -458,9 +464,14 @@
     include 'error.php';
 } elseif ((!isset($_SESSION['validite_pw']) || empty($_SESSION['validite_pw']) || empty($_SESSION['user_id'])) && isset($_GET['otv']) && $_GET['otv'] == "true") {
     // case where one-shot viewer
-    if (isset($_GET['session']) && !empty($_GET['session'])) {
-        include 'otv.php?session='.$_GET['session'];
-    } else {
+	if (
+		isset($_GET['code']) && !empty($_GET['code'])
+		&& isset($_GET['item_id']) && !empty($_GET['item_id'])
+		&& isset($_GET['stamp']) && !empty($_GET['stamp'])
+		&& isset($_GET['otv_id'])
+	) {
+		include 'otv.php';
+	} else {
         $_SESSION['error']['code'] = ERR_VALID_SESSION;
         $_SESSION['initial_url'] = substr($_SERVER["REQUEST_URI"], strpos($_SERVER["REQUEST_URI"], "index.php?"));
         include 'error.php';
```
