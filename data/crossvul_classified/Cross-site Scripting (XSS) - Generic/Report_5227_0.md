# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5227_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5227_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 472-512 of the vulnerable file.

	return(( (int)$p_page_number -1 ) * (int)$p_per_page );
}

/**
 * Make sure that our filters are entirely correct and complete (it is possible that they are not).
 * We need to do this to cover cases where we don't have complete control over the filters given.
 * @param array $p_filter_arr A Filter definition.
 * @return array
 * @todo function needs to be abstracted
 */
function filter_ensure_valid_filter( array $p_filter_arr ) {
	# extend current filter to add information passed via POST
	if( !isset( $p_filter_arr['_version'] ) ) {
		$p_filter_arr['_version'] = FILTER_VERSION;
	}
	$t_cookie_vers = (int)substr( $p_filter_arr['_version'], 1 );
	if( substr( FILTER_VERSION, 1 ) > $t_cookie_vers ) {
		# if the version is old, update it
		$p_filter_arr['_version'] = FILTER_VERSION;
	}
	if( !isset( $p_filter_arr['_view_type'] ) ) {
		$p_filter_arr['_view_type'] = gpc_get_string( 'view_type', 'simple' );
	}
	if( !isset( $p_filter_arr[FILTER_PROPERTY_ISSUES_PER_PAGE] ) ) {
		$p_filter_arr[FILTER_PROPERTY_ISSUES_PER_PAGE] = gpc_get_int( FILTER_PROPERTY_ISSUES_PER_PAGE, config_get( 'default_limit_view' ) );
	}
	if( !isset( $p_filter_arr[FILTER_PROPERTY_HIGHLIGHT_CHANGED] ) ) {
		$p_filter_arr[FILTER_PROPERTY_HIGHLIGHT_CHANGED] = config_get( 'default_show_changed' );
	}
	if( !isset( $p_filter_arr[FILTER_PROPERTY_STICKY] ) ) {
		$p_filter_arr[FILTER_PROPERTY_STICKY] = gpc_string_to_bool( config_get( 'show_sticky_issues' ) );
	}
	if( !isset( $p_filter_arr[FILTER_PROPERTY_SORT_FIELD_NAME] ) ) {
		$p_filter_arr[FILTER_PROPERTY_SORT_FIELD_NAME] = 'last_updated';
	}
	if( !isset( $p_filter_arr[FILTER_PROPERTY_SORT_DIRECTION] ) ) {
		$p_filter_arr[FILTER_PROPERTY_SORT_DIRECTION] = 'DESC';
	}

	if( !isset( $p_filter_arr[FILTER_PROPERTY_PLATFORM] ) ) {
		$p_filter_arr[FILTER_PROPERTY_PLATFORM] = array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -489,9 +489,15 @@
 		# if the version is old, update it
 		$p_filter_arr['_version'] = FILTER_VERSION;
 	}
+
+	# Filter view type - ensure it's either 'simple' or 'advanced' (prevent XSS)
 	if( !isset( $p_filter_arr['_view_type'] ) ) {
 		$p_filter_arr['_view_type'] = gpc_get_string( 'view_type', 'simple' );
 	}
+	if( $p_filter_arr['_view_type'] !== 'advanced' ) {
+		$p_filter_arr['_view_type'] = 'simple';
+	}
+
 	if( !isset( $p_filter_arr[FILTER_PROPERTY_ISSUES_PER_PAGE] ) ) {
 		$p_filter_arr[FILTER_PROPERTY_ISSUES_PER_PAGE] = gpc_get_int( FILTER_PROPERTY_ISSUES_PER_PAGE, config_get( 'default_limit_view' ) );
 	}
```
