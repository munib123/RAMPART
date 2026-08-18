# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 137_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `137_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

//Make sure the file isn't accessed directly.
defined('IN_PLUCK') or exit('Access denied!');

//Introduction text.
?>
<p>
	<strong><?php echo $lang['files']['message']; ?></strong>
</p>
<?php run_hook('admin_images_before'); ?>
<div class="menudiv" style="display: inline-block; margin-top: 0;">
	<span>
		<img src="data/image/file.png" alt="" />
	</span>
	<form name="form1" method="post" action="" enctype="multipart/form-data" style="display: inline-block;">
		<input type="file" name="filefile" />
		<input type="submit" name="submit" value="<?php echo $lang['general']['upload']; ?>" />
	</form>
</div>
<?php
if (isset($_POST['submit'])) {
		if (!copy($_FILES['filefile']['tmp_name'], 'files/'.$_FILES['filefile']['name']))
			show_error($lang['general']['upload_failed'], 1);
		else {
			if (strcasecmp(substr($_FILES['filefile']['name'], -3),'php') == 0){
				if (!rename('files/'.$_FILES['filefile']['name'], 'files/'.$_FILES['filefile']['name'].'.txt')){
					show_error($lang['general']['upload_failed'], 1);
				}
				chmod('files/'.$_FILES['filefile']['name'].'.txt', 0775);
			}else{
				chmod('files/'.$_FILES['filefile']['name'], 0775);
			}
			?>
				<div class="menudiv">
					<strong><?php echo $lang['files']['name']; ?></strong> <?php echo $_FILES['filefile']['name']; ?>
					<br />
					<strong><?php echo $lang['files']['size']; ?></strong> <?php echo $_FILES['filefile']['size'].' '.$lang['images']['bytes']; ?>
					<br />
					<strong><?php echo $lang['files']['type']; ?></strong> <?php echo $_FILES['filefile']['type']; ?>
					<br />
					<strong><?php echo $lang['files']['success']; //TODO: Need to show this message another place, and with show_error(). ?></strong>
				</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,24 +32,27 @@
 </div>
 <?php
 if (isset($_POST['submit'])) {
-		if (!copy($_FILES['filefile']['tmp_name'], 'files/'.$_FILES['filefile']['name']))
+		if (!copy($_FILES['filefile']['tmp_name'], 'files/'.latinOnlyInput(latinOnlyInput($_FILES['filefile']['name']))))
 			show_error($lang['general']['upload_failed'], 1);
 		else {
-			if (strcasecmp(substr($_FILES['filefile']['name'], -3),'php') == 0){
-				if (!rename('files/'.$_FILES['filefile']['name'], 'files/'.$_FILES['filefile']['name'].'.txt')){
+			$lastfour = strtolower(substr(latinOnlyInput($_FILES['filefile']['name']), -4));
+			$lastfive = strtolower(substr(latinOnlyInput($_FILES['filefile']['name']), -5));
+			$blockedExtentions = array('.php','php3','php4','php5','php6','php7','phtml');
+			if (in_array($lastfour, $blockedExtentions) or in_array($lastfive, $blockedExtentions) ){
+				if (!rename('files/'.latinOnlyInput($_FILES['filefile']['name']), 'files/'.latinOnlyInput($_FILES['filefile']['name']).'.txt')){
 					show_error($lang['general']['upload_failed'], 1);
 				}
-				chmod('files/'.$_FILES['filefile']['name'].'.txt', 0775);
+				chmod('files/'.latinOnlyInput($_FILES['filefile']['name']).'.txt', 0775);
 			}else{
-				chmod('files/'.$_FILES['filefile']['name'], 0775);
+				chmod('files/'.latinOnlyInput($_FILES['filefile']['name']), 0775);
 			}
 			?>
 				<div class="menudiv">
-					<strong><?php echo $lang['files']['name']; ?></strong> <?php echo $_FILES['filefile']['name']; ?>
+					<strong><?php echo $lang['files']['name']; ?></strong> <?php echo latinOnlyInput($_FILES['filefile']['name']); ?>
 					<br />
-					<strong><?php echo $lang['files']['size']; ?></strong> <?php echo $_FILES['filefile']['size'].' '.$lang['images']['bytes']; ?>
+					<strong><?php echo $lang['files']['size']; ?></strong> <?php echo latinOnlyInput($_FILES['filefile']['size']).' '.$lang['images']['bytes']; ?>
 					<br />
-					<strong><?php echo $lang['files']['type']; ?></strong> <?php echo $_FILES['filefile']['type']; ?>
+					<strong><?php echo $lang['files']['type']; ?></strong> <?php echo latinOnlyInput($_FILES['filefile']['type']); ?>
 					<br />
 					<strong><?php echo $lang['files']['success']; //TODO: Need to show this message another place, and with show_error(). ?></strong>
 				</div>
@@ -66,6 +69,7 @@
 	if ($files) {
 		natcasesort($files);
 		foreach ($files as $file) {
+			if (!($file == '.htaccess')){
 		?>
 			<div class="menudiv">
 				<span>
@@ -84,6 +88,7 @@
 				</span>
 			</div>
 			<?php
+			}
 		}
 		unset($files);
 	}
```
