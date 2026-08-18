# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 137_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `137_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

</p>
<?php run_hook('admin_images_before'); ?>
<div class="menudiv" style="display: inline-block; margin-top: 0;">
	<span>
		<img src="data/image/image.png" alt="" />
	</span>
	<form name="form1" method="post" action="" enctype="multipart/form-data" style="display: inline-block;">
		<input type="file" name="imagefile" />
		<input type="submit" name="submit" value="<?php echo $lang['general']['upload']; ?>" />
	</form>
</div>
<?php
if (isset($_POST['submit'])) {
	//Check if the file is JPG, PNG or GIF.
	if (in_array($_FILES['imagefile']['type'], array('image/pjpeg', 'image/jpeg','image/png', 'image/gif'))) {
		/* fix issue 44. Thanks to Klaus.  */
        $imagewhitelist = array('jfif', '.png', '.jpg', '.gif', 'jpeg');  
        if (!in_array(strtolower(substr($_FILES['imagefile']['name'], -4)), $imagewhitelist))
			show_error($lang['general']['upload_failed'], 1);
		/* end of fix issue 44. Thanks to Klaus.  */
		if (!copy($_FILES['imagefile']['tmp_name'], 'images/'.$_FILES['imagefile']['name']))
			show_error($lang['general']['upload_failed'], 1);
		else {
			chmod('images/'.$_FILES['imagefile']['name'], 0666);
			?>
				<div class="menudiv">
					<strong><?php echo $lang['images']['name']; ?></strong> <?php echo $_FILES['imagefile']['name']; ?>
					<br />
					<strong><?php echo $lang['images']['size']; ?></strong> <?php echo $_FILES['imagefile']['size'].' '.$lang['images']['bytes']; ?>
					<br />
					<strong><?php echo $lang['images']['type']; ?></strong> <?php echo $_FILES['imagefile']['type']; ?>
					<br />
					<strong><?php echo $lang['images']['success']; //TODO: Need to show this message another place, and with show_error(). ?></strong>
				</div>
			<?php
		}
	}
}

//Display list of uploaded pictures.
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,17 +39,17 @@
         if (!in_array(strtolower(substr($_FILES['imagefile']['name'], -4)), $imagewhitelist))
 			show_error($lang['general']['upload_failed'], 1);
 		/* end of fix issue 44. Thanks to Klaus.  */
-		if (!copy($_FILES['imagefile']['tmp_name'], 'images/'.$_FILES['imagefile']['name']))
+		if (!copy($_FILES['imagefile']['tmp_name'], 'images/'.latinOnlyInput($_FILES['imagefile']['name'])))
 			show_error($lang['general']['upload_failed'], 1);
 		else {
 			chmod('images/'.$_FILES['imagefile']['name'], 0666);
 			?>
 				<div class="menudiv">
-					<strong><?php echo $lang['images']['name']; ?></strong> <?php echo $_FILES['imagefile']['name']; ?>
+					<strong><?php echo $lang['images']['name']; ?></strong> <?php echo latinOnlyInput($_FILES['imagefile']['name']); ?>
 					<br />
-					<strong><?php echo $lang['images']['size']; ?></strong> <?php echo $_FILES['imagefile']['size'].' '.$lang['images']['bytes']; ?>
+					<strong><?php echo $lang['images']['size']; ?></strong> <?php echo latinOnlyInput($_FILES['imagefile']['size']).' '.$lang['images']['bytes']; ?>
 					<br />
-					<strong><?php echo $lang['images']['type']; ?></strong> <?php echo $_FILES['imagefile']['type']; ?>
+					<strong><?php echo $lang['images']['type']; ?></strong> <?php echo latinOnlyInput($_FILES['imagefile']['type']); ?>
 					<br />
 					<strong><?php echo $lang['images']['success']; //TODO: Need to show this message another place, and with show_error(). ?></strong>
 				</div>
@@ -67,6 +67,7 @@
 	if ($images) {
 		natcasesort($images);
 		foreach ($images as $image) {
+			if (!($image == '.htaccess')){
 		?>
 			<div class="menudiv">
 				<span>
@@ -85,6 +86,7 @@
 				</span>
 			</div>
 			<?php
+			}
 		}
 		unset($images);
 	}
```
