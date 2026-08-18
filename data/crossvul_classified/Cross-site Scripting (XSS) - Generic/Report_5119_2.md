# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5119_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5119_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 41-66 of the vulnerable file.

		helper_ensure_confirmed( lang_get( 'confirm_used_custom_field_deletion' ) .
			'<br />' . lang_get( 'custom_field' ) . ': ' . string_attribute( $t_definition['name'] ),
			lang_get( 'field_delete_button' ) );
	} else {
		helper_ensure_confirmed( lang_get( 'confirm_custom_field_deletion' ) .
			'<br />' . lang_get( 'custom_field' ) . ': ' . string_attribute( $t_definition['name'] ),
			lang_get( 'field_delete_button' ) );
	}

	custom_field_destroy( $f_field_id );

	form_security_purge('manage_custom_field_delete');

	html_page_top( null, $f_return );
?>

<br />
<div align="center">
<?php
	echo lang_get( 'operation_successful' ) . '<br />';
	print_bracket_link( $f_return, lang_get( 'proceed' ) );
?>
</div>

<?php
	html_page_bottom();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,7 +58,7 @@
 <div align="center">
 <?php
 	echo lang_get( 'operation_successful' ) . '<br />';
-	print_bracket_link( $f_return, lang_get( 'proceed' ) );
+	print_bracket_link( string_sanitize_url( $f_return ), lang_get( 'proceed' ) );
 ?>
 </div>
 
```
