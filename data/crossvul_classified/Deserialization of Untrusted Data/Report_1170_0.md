# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 1170_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1170_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 3083-3123 of the vulnerable file.

}

/** cleans up a CDEF/VDEF string
 * the CDEF/VDEF must have passed all magic string replacements beforehand
 * @arg string $cdef   - the CDEF/VDEF to be sanitized
 * @returns string    - the sanitized CDEF/VDEF
 */
function sanitize_cdef($cdef) {
	static $drop_char_match =   array('^', '$', '<', '>', '`', '\'', '"', '|', '[', ']', '{', '}', ';', '!');
	static $drop_char_replace = array( '', '',  '',  '',  '',  '',   '',  '',  '',  '',  '',  '',  '',  '');

	return str_replace($drop_char_match, $drop_char_replace, $cdef);
}

/** verifies all selected items are numeric to guard against injection
 * @arg array $items   - an array of serialized items from a post
 * @returns array      - the sanitized selected items array
 */
function sanitize_unserialize_selected_items($items) {
	if ($items != '') {
		$items = unserialize(stripslashes($items));

		if (is_array($items)) {
			foreach ($items as $item) {
				if (is_array($item)) {
					return false;
				} elseif (!is_numeric($item) && ($item != '')) {
					return false;
				}
			}
		} else {
			return false;
		}
	} else {
		return false;
	}

	return $items;
}

function cacti_escapeshellcmd($string) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3100,15 +3100,22 @@
  */
 function sanitize_unserialize_selected_items($items) {
 	if ($items != '') {
-		$items = unserialize(stripslashes($items));
-
-		if (is_array($items)) {
-			foreach ($items as $item) {
-				if (is_array($item)) {
-					return false;
-				} elseif (!is_numeric($item) && ($item != '')) {
-					return false;
+		$unstripped = stripslashes($items);
+
+		// validate that sanitized string is correctly formatted
+		if (preg_match('/^a:[0-9]+:{/', $unstripped) && !preg_match('/(^|;|{|})O:\+?[0-9]+:"/', $unstripped)) {
+			$items = unserialize($unstripped);
+
+			if (is_array($items)) {
+				foreach ($items as $item) {
+					if (is_array($item)) {
+						return false;
+					} elseif (!is_numeric($item) && ($item != '')) {
+						return false;
+					}
 				}
+			} else {
+				return false;
 			}
 		} else {
 			return false;
```
