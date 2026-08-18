# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2361_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2361_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 53-79 of the vulnerable file.

# The comparison is not case sensitive.
# Returns the array of the filtered strings, or an empty array.  If the input array has non-unique
# entries, then the output one may contain duplicates.
function projax_array_filter_by_prefix( $p_array, $p_prefix ) {
	$t_matches = array();

	foreach( $p_array as $t_entry ) {
		if( utf8_strtolower( utf8_substr( $t_entry, 0, utf8_strlen( $p_prefix ) ) ) == utf8_strtolower( $p_prefix ) ) {
			$t_matches[] = $t_entry;
		}
	}

	return $t_matches;
}

# Serializes the provided array of strings into the format expected by the auto-complete library.
function projax_array_serialize_for_autocomplete( $p_array ) {
	$t_matches = '<ul>';

	foreach( $p_array as $t_entry ) {
		$t_matches .= "<li>$t_entry</li>";
	}

	$t_matches .= '</ul>';

	return $t_matches;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,7 +70,7 @@
 	$t_matches = '<ul>';
 
 	foreach( $p_array as $t_entry ) {
-		$t_matches .= "<li>$t_entry</li>";
+		$t_matches .= '<li>' . string_attribute( $t_entry ) . '</li>';
 	}
 
 	$t_matches .= '</ul>';
```
