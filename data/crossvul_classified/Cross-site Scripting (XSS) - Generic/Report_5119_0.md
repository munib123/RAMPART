# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5119_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5119_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 98-120 of the vulnerable file.

				$t_prefs->timezone = '';
			} else {
				$t_prefs->timezone = $t_timezone;
			}
		}
	}

	event_signal( 'EVENT_ACCOUNT_PREF_UPDATE', array( $f_user_id ) );

	user_pref_set( $f_user_id, $t_prefs );

	form_security_purge( 'account_prefs_update' );

	html_page_top( null, $f_redirect_url );

	echo '<br /><div align="center">';

	echo lang_get( 'operation_successful' );

	echo '<br />';
	print_bracket_link( $f_redirect_url, lang_get( 'proceed' ) );
	echo '<br /></div>';
	html_page_bottom();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,6 +115,6 @@
 	echo lang_get( 'operation_successful' );
 
 	echo '<br />';
-	print_bracket_link( $f_redirect_url, lang_get( 'proceed' ) );
+	print_bracket_link( string_sanitize_url( $f_redirect_url ), lang_get( 'proceed' ) );
 	echo '<br /></div>';
 	html_page_bottom();
```
