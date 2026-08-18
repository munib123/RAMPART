# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 710_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `710_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 17-57 of the vulnerable file.


//Introduction text.
?>
<p>
	<strong><?php echo $lang['images']['message']; ?></strong>
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,9 +34,13 @@
 if (isset($_POST['submit'])) {
 	//Check if the file is JPG, PNG or GIF.
 	if (in_array($_FILES['imagefile']['type'], array('image/pjpeg', 'image/jpeg','image/png', 'image/gif'))) {
+		/* fix issue 44. Thanks to Klaus.  */
+        $imagewhitelist = array('jfif', '.png', '.jpg', '.gif', 'jpeg');  
+        if (!in_array(strtolower(substr($_FILES['imagefile']['name'], -4)), $imagewhitelist))
+			show_error($lang['general']['upload_failed'], 1);
+		/* end of fix issue 44. Thanks to Klaus.  */
 		if (!copy($_FILES['imagefile']['tmp_name'], 'images/'.$_FILES['imagefile']['name']))
 			show_error($lang['general']['upload_failed'], 1);
-
 		else {
 			chmod('images/'.$_FILES['imagefile']['name'], 0666);
 			?>
```
