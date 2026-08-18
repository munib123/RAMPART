# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 377_5
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `377_5`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 142-182 of the vulnerable file.

					'mtime' => filemtime (self::root () . $path . '/' . $entry),
					'fsize' => filesize (self::root () . $path . '/' . $entry)
				);
			}
		}
		$d->close ();
		usort ($out['dirs'], array ('FileManager', 'fsort'));
		usort ($out['files'], array ('FileManager', 'fsort'));
		return $out;
	}

	/**
	 * Delete a file.
	 */
	public static function unlink ($file) {
		if (self::verify_folder ($file)) {
			self::$error = __ ('Unable to delete folders');
			return false;
		} elseif (! self::verify_file ($file)) {
			self::$error = __ ('File not found');
			return false;
		} elseif (! unlink (self::root () . $file)) {
			self::$error = __ ('Unable to delete') . ' ' . $file;
			return false;
		}
		self::prop_delete ($file);
		return true;
	}

	/**
	 * Rename a file or folder.
	 */
	public static function rename ($file, $new_name) {
		if (self::verify_folder ($file)) {
			if (! self::verify_folder_name ($new_name)) {
				self::$error = __ ('Invalid folder name');
				return false;
			}
			$parts = explode ('/', $file);
			$old = array_pop ($parts);
			$new = preg_replace ('/' . preg_quote ($old) . '$/', $new_name, $file);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -160,6 +160,9 @@
 		} elseif (! self::verify_file ($file)) {
 			self::$error = __ ('File not found');
 			return false;
+		} elseif (! self::verify_file_name ($file)) {
+			self::$error = __ ('Invalid file name');
+			return false;
 		} elseif (! unlink (self::root () . $file)) {
 			self::$error = __ ('Unable to delete') . ' ' . $file;
 			return false;
@@ -405,7 +408,7 @@
 		if (! preg_match ('/^[a-zA-Z0-9 _-]+\.[a-zA-Z0-9_-]+$/', $name)) {
 			return false;
 		}
-		if (preg_match ('/\.php$/i', $name)) {
+		if (preg_match ('/\.(php|phtml|pht|php3|php4|php5|phar|js|rb|py|pl|sh|bash|exe|htaccess|htpasswd)$/i', $name)) {
 			return false;
 		}
 		return true;
```
