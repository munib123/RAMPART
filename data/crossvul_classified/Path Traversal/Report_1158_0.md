# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 1158_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1158_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 68-108 of the vulnerable file.

		) {
		//get the uuid
			$stream_uuid = $_GET['id'];

		//get the record
			foreach($streams as $row) {
				if ($stream_uuid == $row['music_on_hold_uuid']) {
					$stream_domain_uuid = $row['domain_uuid'];
					$stream_name = $row['music_on_hold_name'];
					$stream_path = $row['music_on_hold_path'];
					break;
				}
			}
		
		//replace the sounds_dir variable in the path
			$stream_path = str_replace('$${sounds_dir}', $_SESSION['switch']['sounds']['dir'], $stream_path);

		//get the file
			$stream_file = base64_decode($_GET['file']);
			$stream_full_path = path_join($stream_path, $stream_file);

		//dowload the file
			session_cache_limiter('public');
			if (file_exists($stream_full_path)) {
				$fd = fopen($stream_full_path, "rb");
				if ($_GET['t'] == "bin") {
					header("Content-Type: application/force-download");
					header("Content-Type: application/octet-stream");
					header("Content-Type: application/download");
					header("Content-Description: File Transfer");
				}
				else {
					$stream_file_ext = pathinfo($stream_file, PATHINFO_EXTENSION);
					switch ($stream_file_ext) {
						case "wav" : header("Content-Type: audio/x-wav"); break;
						case "mp3" : header("Content-Type: audio/mpeg"); break;
						case "ogg" : header("Content-Type: audio/ogg"); break;
					}
				}
				header('Content-Disposition: attachment; filename="'.$stream_file.'"');
				header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,6 +85,9 @@
 		//get the file
 			$stream_file = base64_decode($_GET['file']);
 			$stream_full_path = path_join($stream_path, $stream_file);
+
+		//sanitize path
+			$stream_full_path = str_replace('../', '', $stream_full_path);
 
 		//dowload the file
 			session_cache_limiter('public');
@@ -284,13 +287,21 @@
 				}
 			}
 
+		//replace the sounds_dir variable in the path
+			$stream_path = str_replace('$${sounds_dir}', $_SESSION['switch']['sounds']['dir'], $stream_path);
+
 		//check permissions
 			if (($stream_domain_uuid == '' && permission_exists('music_on_hold_domain')) ||
 				($stream_domain_uuid != '' && permission_exists('music_on_hold_delete'))) {
 
 				//remove specified file
 					if ($stream_file != '') {
-						@unlink(path_join($stream_path, $stream_file));
+						//define path
+							$stream_full_path = path_join($stream_path, $stream_file);
+						//sanitize path
+							$stream_full_path = str_replace('../', '', $stream_full_path);
+						//delete file
+							@unlink($stream_full_path);
 					}
 				//remove all audio files
 					else {
```
