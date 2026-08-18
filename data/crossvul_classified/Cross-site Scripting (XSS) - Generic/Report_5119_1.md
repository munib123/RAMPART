# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5119_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5119_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 48-73 of the vulnerable file.

		# Confirm with the user
		helper_ensure_confirmed( lang_get( 'config_delete_sure' ) . lang_get( 'word_separator' ) . 
			string_html_specialchars( implode( ', ', $t_revert_vars ) ) . ' ' . lang_get( 'in_project' ) . ' ' . project_get_name( $f_project_id ),
			lang_get( 'delete_config_button' ) );

		foreach ( $t_revert_vars as $t_revert ) {
			config_delete( $t_revert, null , $f_project_id );
		}
	}

	form_security_purge('manage_config_revert');

	$t_redirect_url = $f_return;

	html_page_top( null, $t_redirect_url );
?>
<br />
<div align="center">
<?php
	echo lang_get( 'operation_successful' ).'<br />';
	print_bracket_link( $t_redirect_url, lang_get( 'proceed' ) );
?>
</div>

<?php
	html_page_bottom();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,7 +65,7 @@
 <div align="center">
 <?php
 	echo lang_get( 'operation_successful' ).'<br />';
-	print_bracket_link( $t_redirect_url, lang_get( 'proceed' ) );
+	print_bracket_link( string_sanitize_url( $t_redirect_url ), lang_get( 'proceed' ) );
 ?>
 </div>
 
```
