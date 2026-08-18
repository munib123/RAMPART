# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 4314_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4314_3`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 67-108 of the vulnerable file.

				$parent[$partv] = [];
			$parent = &$parent[$partv];
		}
		if (empty($parent[$leafKey]))
			$parent[$leafKey] = $value;
	}
	return $return;
}

/**
 * Sort an array by values using a user-defined key.
 * @ingroup api
 * @param array The array to sort.
 * @param key The key used as sort criteria.
 * @return Returns TRUE on success or FALSE on failure.
 */
function array_sort_key(array &$array, $key) {
	if (!is_multi_array($array))
		return FALSE;
	// Sort the array.
	if (FALSE === uasort($array, create_function('$a, $b',
		"return strnatcmp(strval(\$a['$key']), strval(\$b['$key']));")))
		return FALSE;
	// Re-index the array.
	$array = array_values($array);
	return TRUE;
}

/**
 * Remove an key from the given array.
 * @param array $array The array to remove the key from.
 * @param mixed $key The key to be removed.
 * @return Returns TRUE on success, otherwise FALSE.
 */
function array_remove_key(array &$array, $key) {
	if (FALSE === array_key_exists($key, $array))
		return FALSE;
	unset($array[$key]);
	return TRUE;
}

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,9 +84,11 @@
 	if (!is_multi_array($array))
 		return FALSE;
 	// Sort the array.
-	if (FALSE === uasort($array, create_function('$a, $b',
-		"return strnatcmp(strval(\$a['$key']), strval(\$b['$key']));")))
-		return FALSE;
+	if (FALSE === uasort($array, function($a, $b) use($key) {
+		return strnatcmp(strval($a[$key]), strval($b[$key]));
+	})) {
+		return FALSE;
+	}
 	// Re-index the array.
 	$array = array_values($array);
 	return TRUE;
```
