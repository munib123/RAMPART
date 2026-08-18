# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 4314_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4314_2`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 314-354 of the vulnerable file.


	/**
	 * Compare the configuration from the given XPath expression with the
	 * given data.
	 * @param xpath The XPath expression to execute.
	 * @param data The data to compare.
	 * @return Returns 0 if the data is equal, otherwise -1. On error
	 *   boolean FALSE is returned.
	 */
	public function compare($xpath, $data) {
		if (is_null($result = $this->get($xpath)))
			return FALSE;
		// Convert everything into an array.
		if (!is_array($result))
			$result = array($result);
		if (!is_array($data))
			$result = array($data);
		// Convert all values to strings before comparison. This is necessary
		// because the values returned from the configuration database are
		// strings.
		if (FALSE === array_walk_recursive($data,
		  create_function('&$item, $key', 'if (is_string($item)) { '.
		  'if (!mb_check_encoding($item, "UTF-8")) { '.
		  '$item = utf8_encode($item); } } else { '.
		  '$item = utf8_encode(strval($item)); }')))
			return FALSE;
		// Compare the arrays.
		if (0 == count(array_diff($result, $data)))
			return 0;
		return -1;
	}

	/**
	 * Revert changes. All existing revision files will be deleted.
	 * @param filename The revision file. Defaults to NONE.
	 * @note This only takes action if versioning is enabled.
	 * @return void
	 */
	public function revert($filename) {
		if (TRUE !== $this->versioning)
			throw new DatabaseException("Versioning is not enabled.");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -331,6 +331,17 @@
 		// Convert all values to strings before comparison. This is necessary
 		// because the values returned from the configuration database are
 		// strings.
+		if (FALSE === array_walk_recursive($data, function(&$item, $key) {
+			if (is_string($item)) {
+				if (!mb_check_encoding($item, "UTF-8")) {
+					$item = utf8_encode($item);
+				}
+			} else {
+				$item = utf8_encode(strval($item));
+			}
+		})) {
+			return FALSE;
+		}
 		if (FALSE === array_walk_recursive($data,
 		  create_function('&$item, $key', 'if (is_string($item)) { '.
 		  'if (!mb_check_encoding($item, "UTF-8")) { '.
@@ -338,8 +349,12 @@
 		  '$item = utf8_encode(strval($item)); }')))
 			return FALSE;
 		// Compare the arrays.
-		if (0 == count(array_diff($result, $data)))
+		// Note, we can not use `array_diff` here because this function
+		// does not support multidimensional arrays.
+		if (0 === strcmp(json_encode_safe($result),
+				json_encode_safe($data))) {
 			return 0;
+		}
 		return -1;
 	}
 
```
