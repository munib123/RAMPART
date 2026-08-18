# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5119_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5119_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 62-84 of the vulnerable file.

	$t_user_print_pref_table = db_get_table( 'mantis_user_print_pref_table' );
	$query = "UPDATE $t_user_print_pref_table
			SET print_pref=" . db_param() . "
			WHERE user_id=" . db_param();

	$result = db_query_bound( $query, Array( $c_export, $t_user_id ) );

	form_security_purge( 'print_all_bug_options_update' );

	html_page_top( null, $f_redirect_url );

	echo '<br /><div align="center">';

	if ( $result ) {
		print lang_get( 'operation_successful' );
	} else {
		print error_string( ERROR_GENERIC );
	}

	echo '<br />';
	print_bracket_link( $f_redirect_url, lang_get( 'proceed' ) );
	echo '<br /></div>';
	html_page_bottom();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,6 +79,6 @@
 	}
 
 	echo '<br />';
-	print_bracket_link( $f_redirect_url, lang_get( 'proceed' ) );
+	print_bracket_link( string_sanitize_url( $f_redirect_url ), lang_get( 'proceed' ) );
 	echo '<br /></div>';
 	html_page_bottom();
```
