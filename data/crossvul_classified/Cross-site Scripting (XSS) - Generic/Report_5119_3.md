# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5119_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5119_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 47-71 of the vulnerable file.

	$t_values['display_update']		= gpc_get_bool( 'display_update' );
	$t_values['display_resolved']	= gpc_get_bool( 'display_resolved' );
	$t_values['display_closed']		= gpc_get_bool( 'display_closed' );
	$t_values['require_report']		= gpc_get_bool( 'require_report' );
	$t_values['require_update']		= gpc_get_bool( 'require_update' );
	$t_values['require_resolved']	= gpc_get_bool( 'require_resolved' );
	$t_values['require_closed']		= gpc_get_bool( 'require_closed' );
	$t_values['filter_by']			= gpc_get_bool( 'filter_by' );

	custom_field_update( $f_field_id, $t_values );

	form_security_purge('manage_custom_field_update');

	html_page_top( null, $f_return );

	echo '<br />';
	echo '<div align="center">';

	echo lang_get( 'operation_successful' ) . '<br />';

	print_bracket_link( $f_return, lang_get( 'proceed' ) );

	echo '</div>';

	html_page_bottom();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,7 +64,7 @@
 
 	echo lang_get( 'operation_successful' ) . '<br />';
 
-	print_bracket_link( $f_return, lang_get( 'proceed' ) );
+	print_bracket_link( string_sanitize_url( $f_return ), lang_get( 'proceed' ) );
 
 	echo '</div>';
 
```
