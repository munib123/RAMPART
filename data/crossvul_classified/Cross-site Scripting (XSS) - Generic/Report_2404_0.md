# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2404_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2404_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 235-276 of the vulnerable file.


	$t_path = rtrim( config_get( 'path' ), '/' );
	$t_short_path = rtrim( config_get( 'short_path' ), '/' );

	$t_pattern = '(?:/*(?P<script>[^\?#]*))(?:\?(?P<query>[^#]*))?(?:#(?P<anchor>[^#]*))?';

	# Break the given URL into pieces for path, script, query, and anchor
	$t_type = 0;
	if ( preg_match( '@^(?P<path>' . preg_quote( $t_path, '@' ) . ')' . $t_pattern . '$@', $t_url, $t_matches ) ) {
		$t_type = 1;
	} else if ( !empty( $t_short_path )
			 && preg_match( '@^(?P<path>' . preg_quote( $t_short_path, '@' ) . ')' . $t_pattern . '$@', $t_url, $t_matches )
	) {
		$t_type = 2;
	} else if ( preg_match( '@^(?P<path>)' . $t_pattern . '$@', $t_url, $t_matches ) ) {
		$t_type = 3;
	}

	# Check for URL's pointing to other domains
	if ( 0 == $t_type || empty( $t_matches['script'] ) ||
		3 == $t_type && preg_match( '@(?:[^:]*)?://@', $t_url ) > 0 ) {

		return ( $p_return_absolute ? $t_path . '/' : '' ) . 'index.php';
	}

	# Start extracting regex matches
	$t_script = $t_matches['script'];
	$t_script_path = $t_matches['path'];

	# Clean/encode query params
	$t_query = '';
	if ( isset( $t_matches['query'] ) ) {
		$t_pairs = array();
		parse_str( html_entity_decode( $t_matches['query'] ), $t_pairs );

		$t_clean_pairs = array();
		foreach( $t_pairs as $t_key => $t_value ) {
			if ( is_array( $t_value ) ) {
				foreach( $t_value as $t_value_each ) {
					$t_clean_pairs[] .= rawurlencode( $t_key ) . '[]=' . rawurlencode( $t_value_each );
				}
			} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -252,8 +252,7 @@
 
 	# Check for URL's pointing to other domains
 	if ( 0 == $t_type || empty( $t_matches['script'] ) ||
-		3 == $t_type && preg_match( '@(?:[^:]*)?://@', $t_url ) > 0 ) {
-
+		3 == $t_type && preg_match( '@(?:[^:]*)?:/*@', $t_url ) > 0 ) {
 		return ( $p_return_absolute ? $t_path . '/' : '' ) . 'index.php';
 	}
 
```
