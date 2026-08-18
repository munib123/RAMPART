# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 211_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `211_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2377-2417 of the vulnerable file.

	$t_filter = filter_ensure_valid_filter( $p_filter );
	$t_view_type = $t_filter['_view_type'];
	$t_source_query_id = isset( $t_filter['_source_query_id'] ) ? (int)$t_filter['_source_query_id'] : -1;

	# If it's a stored filter, linked to a specific project, use that project_id to render available fields
	if( $t_source_query_id > 0 ) {
		$t_project_id = (int)filter_get_field( $t_source_query_id, 'project_id' );
		if( ALL_PROJECTS == $t_project_id ) {
			# If all_projects, the filter can be used at any project, select the current project id
			$t_project_id = helper_get_current_project();
		} else if( $t_project_id < 0 ) {
			# If filter is an unnamed filter, project id is stored as negative value.
			$t_project_id = -1 * $t_project_id;
		}
	} else {
		$t_project_id = helper_get_current_project();
	}

	if( null === $p_static_fallback_page ) {
		$p_static_fallback_page = $_SERVER['PHP_SELF'];
	}
	$t_filters_url = $p_static_fallback_page;
	$t_get_params = $_GET;
	$t_get_params['for_screen'] = $p_for_screen;
	$t_get_params['static'] = ON;
	$t_get_params['view_type'] = ( FILTER_VIEW_TYPE_ADVANCED == $t_view_type )
		? FILTER_VIEW_TYPE_ADVANCED
		: FILTER_VIEW_TYPE_SIMPLE;
	$t_filters_url .= '?' . http_build_query( $t_get_params );

	$t_show_product_version =  version_should_show_product_version( $t_project_id );
	$t_show_build = $t_show_product_version && ( config_get( 'enable_product_build' ) == ON );

	# overload handler_id setting if user isn't supposed to see them (ref #6189)
	if( !access_has_any_project_level( 'view_handler_threshold' ) ) {
		$t_filter[FILTER_PROPERTY_HANDLER_ID] = array(
			META_FILTER_ANY,
		);
	}

	if ( config_get( 'use_dynamic_filters' ) ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2394,6 +2394,7 @@
 
 	if( null === $p_static_fallback_page ) {
 		$p_static_fallback_page = $_SERVER['PHP_SELF'];
+		$p_static_fallback_page = string_sanitize_url( $_SERVER['PHP_SELF'] );
 	}
 	$t_filters_url = $p_static_fallback_page;
 	$t_get_params = $_GET;
```
