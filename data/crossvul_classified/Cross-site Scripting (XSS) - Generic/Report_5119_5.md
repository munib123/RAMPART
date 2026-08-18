# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5119_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5119_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 92-117 of the vulnerable file.

				$t_redirect_url = $t_home_page;
			}
		} else {
			$t_redirect_url = $t_home_page;
		}
	}

	print_header_redirect( $t_redirect_url, true, true );

	html_page_top1();
	html_meta_redirect( $t_redirect_url );

	html_page_top1();
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
@@ -109,7 +109,7 @@
 <?php
 	echo lang_get( 'operation_successful' ).'<br />';
 
-	print_bracket_link( $t_redirect_url, lang_get( 'proceed' ) );
+	print_bracket_link( string_sanitize_url( $t_redirect_url ), lang_get( 'proceed' ) );
 ?>
 </div>
 
```
