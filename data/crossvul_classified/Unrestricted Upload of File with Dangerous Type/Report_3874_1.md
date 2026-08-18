# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 3874_1
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3874_1`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php
/**
 * admin_edit_room.php
 * Interface de creation/modification des sites, domaines et des ressources de l'application GRR
 * Ce script fait partie de l'application GRR
 * Dernière modification : $Date: 2020-01-28 11:10$
 * @author    Laurent Delineau & JeromeB & Marc-Henri PAMISEU & Yan Naessens & Daniel Antelme
 * @copyright Copyright 2003-2020 Team DEVOME - JeromeB
 * @link      http://www.gnu.org/licenses/licenses.html
 *
 * This file is part of GRR.
 *
 * GRR is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
$grr_script_name = "admin_edit_room.php";

include "../include/admin.inc.php";

$ok = NULL;
if (Settings::get("module_multisite") == "Oui")
	$id_site = isset($_POST["id_site"]) ? $_POST["id_site"] : (isset($_GET["id_site"]) ? $_GET["id_site"] : -1);
$action = isset($_POST["action"]) ? $_POST["action"] : (isset($_GET["action"]) ? $_GET["action"] : NULL);
$add_area = isset($_POST["add_area"]) ? $_POST["add_area"] : (isset($_GET["add_area"]) ? $_GET["add_area"] : NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
  * admin_edit_room.php
  * Interface de creation/modification des sites, domaines et des ressources de l'application GRR
  * Ce script fait partie de l'application GRR
- * Dernière modification : $Date: 2020-01-28 11:10$
+ * Dernière modification : $Date: 2020-03-13 12:30$
  * @author    Laurent Delineau & JeromeB & Marc-Henri PAMISEU & Yan Naessens & Daniel Antelme
  * @copyright Copyright 2003-2020 Team DEVOME - JeromeB
  * @link      http://www.gnu.org/licenses/licenses.html
@@ -171,32 +171,38 @@
 	if (isset($change_room))
 	{
 		if (isset($_POST['sup_img']))
-		{
-			$dest = '../images/';
-			$ok1 = false;
-			if ($f = @fopen("$dest/.test", "w"))
-			{
-				@fputs($f, '<'.'?php $ok1 = true; ?'.'>');
-				@fclose($f);
-				include("$dest/.test");
-			}
-			if (!$ok1)
-			{
-				$msg .= "L\'image n\'a pas pu etre supprimee : probleme d\'écriture sur le repertoire. Veuillez signaler ce problème à l\'administrateur du serveur.\\n";
-				$ok = 'no';
-			}
-			else
-			{
-				if (@file_exists($dest."img_".TABLE_PREFIX."".$room.".jpg"))
-					unlink($dest."img_".TABLE_PREFIX."".$room.".jpg");
-				if (@file_exists($dest."img_".TABLE_PREFIX."".$room.".png"))
-					unlink($dest."img_".TABLE_PREFIX."".$room.".png");
-				if (@file_exists($dest."img_".TABLE_PREFIX."".$room.".gif"))
-					unlink($dest."img_".TABLE_PREFIX."".$room.".gif");
-				$picture_room = "";
-			}
-		}
-		if (empty($capacity))
+        {
+            $dest = '../images/';
+            $ok1 = false;
+            if ($f = @fopen("$dest/.test", "w"))
+            {
+                @fputs($f, '<'.'?php $ok1 = true; ?'.'>');
+                @fclose($f);
+                include("$dest/.test");
+            }
+            if (!$ok1)
+            {
+                $msg .= "L\'image n\'a pas pu etre supprimee : probleme d\'écriture sur le repertoire. Veuillez signaler ce problème à l\'administrateur du serveur.\\n";
+                $ok = 'no';
+            }
+            else
+            {
+                if (@file_exists($dest."img_".TABLE_PREFIX."".$room.".jpg"))
+                    unlink($dest."img_".TABLE_PREFIX."".$room.".jpg");
+                if (@file_exists($dest."img_".TABLE_PREFIX."".$room.".png"))
+                    unlink($dest."img_".TABLE_PREFIX."".$room.".png");
+                if (@file_exists($dest."img_".TABLE_PREFIX."".$room.".gif"))
+                    unlink($dest."img_".TABLE_PREFIX."".$room.".gif");
+                // $picture_room = ""; mettre à jour la donnée room
+                $sql_picture = "UPDATE ".TABLE_PREFIX."_room SET picture_room='' WHERE id=".protect_data_sql($room);
+                if (grr_sql_command($sql_picture) < 0)
+                {
+                    fatal_error(0, get_vocab('update_room_failed') . grr_sql_error());
+                    $ok = 'no';
+                }
+            }
+        }
+        if (empty($capacity))
 			$capacity = 0;
 		if ($capacity < 0)
 			$capacity = 0;
@@ -280,65 +286,102 @@
 			$room_name = get_vocab("room")." ".$room;
 			grr_sql_command("UPDATE ".TABLE_PREFIX."_room SET room_name='".protect_data_sql($room_name)."' WHERE id=$room");
 		}
-		$doc_file = isset($_FILES["doc_file"]) ? $_FILES["doc_file"] : NULL;
-		if (preg_match("`\.([^.]+)$`", $doc_file['name'], $match))
-		{
-			$ext = strtolower($match[1]);
-			if ($ext != 'jpg' && $ext != 'png'&& $ext != 'gif')
-			{
-				$msg .= "L\'image n\'a pas pu etre enregistree : les seules extentions autorisees sont gif, png et jpg.\\n";
-				$ok = 'no';
-			}
-			else
-			{
-				$dest = '../images/';
-				$ok1 = false;
-				if ($f = @fopen("$dest/.test", "w"))
-				{
-					@fputs($f, '<'.'?php $ok1 = true; ?'.'>');
-					@fclose($f);
-					include("$dest/.test");
-				}
-				if (!$ok1)
-				{
-					$msg .= "L\'image n\'a pas pu etre enregistree : probleme d\'ecriture sur le repertoire IMAGES. Veuillez signaler ce probleme e l\'administrateur du serveur.\\n";
-					$ok = 'no';
-				}
-				else
-				{
-					$ok1 = @copy($doc_file['tmp_name'], $dest.$doc_file['name']);
-					if (!$ok1)
-						$ok1 = @move_uploaded_file($doc_file['tmp_name'], $dest.$doc_file['name']);
-					if (!$ok1)
-					{
-						$msg .= "L\'image n\'a pas pu etre enregistree : probleme de transfert. Le fichier n\'a pas pu etre transfere sur le repertoire IMAGES. Veuillez signaler ce probleme e l\'administrateur du serveur.\\n";
-						$ok = 'no';
-					}
-					else
-					{
-						$tab = explode(".", $doc_file['name']);
-						$ext = strtolower($tab[1]);
-						if (@file_exists($dest."img_".TABLE_PREFIX."".$room.".".$ext))
-							@unlink($dest."img_".TABLE_PREFIX."".$room.".".$ext);
-						rename($dest.$doc_file['name'],$dest."img_".TABLE_PREFIX."".$room.".".$ext);
-						@chmod($dest."img_".TABLE_PREFIX."".$room.".".$ext, 0666);
-						$picture_room = "img_".TABLE_PREFIX."".$room.".".$ext;
-						$sql_picture = "UPDATE ".TABLE_PREFIX."_room SET picture_room='".protect_data_sql($picture_room)."' WHERE id=".$room;
-						if (grr_sql_command($sql_picture) < 0)
-						{
-							fatal_error(0, get_vocab('update_room_failed') . grr_sql_error());
-							$ok = 'no';
-						}
-					}
-				}
-			}
-		}
-		else if ($doc_file['name'] != '')
-		{
-			$msg .= "L\'image n\'a pas pu etre enregistree : le fichier image selectionne n'est pas valide !\\n";
-			$ok = 'no';
-		}
-		$msg .= get_vocab("message_records");
+        // image d'illustration
+        $doc_file = isset($_FILES["doc_file"]) ? $_FILES["doc_file"] : NULL;
+        /* Test premier, juste pour bloquer les double extensions */
+        if (count(explode('.', $doc_file['name'])) > 2) {
+            $msg .= "L\'image n\'a pas pu être enregistrée : les seules extentions autorisées sont gif, png et jpg.\\n";
+            $ok = 'no';
+        } 
+        elseif  (preg_match("`\.([^.]+)$`", $doc_file['name'], $match)) {
+            $ext = strtolower($match[1]);
+            if ($ext != 'jpg' && $ext != 'png'&& $ext != 'gif')
+            {
+                $msg .= "L\'image n\'a pas pu etre enregistree : les seules extentions autorisees sont gif, png et jpg.\\n";
+                $ok = 'no';
+            }
+            else {
+                /* deuxième test passé, l'extension est autorisée */
+                /* 3ème test avec fileinfo */
+                $finfo = finfo_open(FILEINFO_MIME_TYPE);
+                $fileType = finfo_file($finfo, $doc_file['tmp_name']);
+                /* 4ème test avec gd pour valider que c'est bien une image malgré tout - nécessaire ou parano ? */
+                switch($fileType) {
+                    case "image/gif":
+                        /* recreate l'image, supprime les data exif */
+                        $logoRecreated = @imagecreatefromgif ( $doc_file['tmp_name'] );
+                        /* fix pour la transparence */
+                        imageAlphaBlending($logoRecreated, true);
+                        imageSaveAlpha($logoRecreated, true);
+                        $extSafe = "gif";
+                        break;
+                    case "image/jpeg":
+                        $logoRecreated = @imagecreatefromjpeg ( $doc_file['tmp_name'] );
+                        $extSafe = "jpg";
+                        break;
+                    case "image/png":
+                        $logoRecreated = @imagecreatefrompng ( $doc_file['tmp_name'] );
+                        /* fix pour la transparence */
+                        imageAlphaBlending($logoRecreated, true);
+                        imageSaveAlpha($logoRecreated, true);
+                        $extSafe = "png";
+                        break;
+                    default:
+                        $msg .= "L\'image n\'a pas pu être enregistrée : type mime incompatible.\\n";
+                        $ok = 'no';
+                        $extSafe = false;
+                        break;
+                }
+            }
+            if (!$logoRecreated || $extSafe === false) {
... (diff truncated)
```
