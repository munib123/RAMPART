# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2179_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2179_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 34-74 of the vulnerable file.

 * SVN : $URL$
 * SVN : $Id$
 * 
 */
	require_once ("@CENTREON_ETC@/centreon.conf.php");		
	require_once ("../../$classdir/centreonSession.class.php");
	require_once ("../../$classdir/centreon.class.php");
	require_once ("../../$classdir/centreonDB.class.php");
	
	$pearDB = new CentreonDB();
	CentreonSession::start();
	$centreon= $_SESSION["centreon"];
	
	$session = $pearDB->query("SELECT * FROM `session` WHERE `session_id` = '".session_id()."'");
	if (!$session->numRows())
		exit;
	
	$logos_path = "../../img/media/";

	if (isset($_GET["id"]) && $_GET["id"] && is_numeric($_GET["id"])) {
	    $result = $pearDB->query("SELECT dir_name, img_path FROM view_img_dir, view_img, view_img_dir_relation vidr WHERE view_img_dir.dir_id = vidr.dir_dir_parent_id AND vidr.img_img_id = img_id AND img_id = '".$_GET["id"]."'");
	    while ($img = $result->fetchRow() ) {
			$imgpath = $logos_path . $img["dir_name"] ."/". $img["img_path"];
	        if (!is_file($imgpath)) {
		        $imgpath = $centreon_path . 'www/img/media/' . $img["dir_name"] ."/". $img["img_path"];
		    }
			if (is_file($imgpath)) {
			    $fd = fopen($imgpath, "r");
			    $buffer = NULL;
			    while (!feof($fd)) {
				    $buffer .= fgets($fd, 4096);
			    }
			    fclose ($fd);
			    print $buffer;
			    break;
			}
			else {
				print "File not found";
			}
	    }	
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,7 @@
 	$logos_path = "../../img/media/";
 
 	if (isset($_GET["id"]) && $_GET["id"] && is_numeric($_GET["id"])) {
-	    $result = $pearDB->query("SELECT dir_name, img_path FROM view_img_dir, view_img, view_img_dir_relation vidr WHERE view_img_dir.dir_id = vidr.dir_dir_parent_id AND vidr.img_img_id = img_id AND img_id = '".$_GET["id"]."'");
+	    $result = $pearDB->query("SELECT dir_name, img_path FROM view_img_dir, view_img, view_img_dir_relation vidr WHERE view_img_dir.dir_id = vidr.dir_dir_parent_id AND vidr.img_img_id = img_id AND img_id = '".$pearDB->escape($_GET["id"])."'");
 	    while ($img = $result->fetchRow() ) {
 			$imgpath = $logos_path . $img["dir_name"] ."/". $img["img_path"];
 	        if (!is_file($imgpath)) {
```
