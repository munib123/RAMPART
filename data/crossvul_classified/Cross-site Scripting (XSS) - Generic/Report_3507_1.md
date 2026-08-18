# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3507_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3507_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 421-461 of the vulnerable file.


#
# Platform, OS, OS Version
#

if ( $tpl_show_platform || $tpl_show_os || $tpl_show_os_version ) {
	echo '<tr ', helper_alternate_class(), '>';

	$t_spacer = 0;

	if ( $tpl_show_platform ) {
		# Platform
		echo '<td class="category">', lang_get( 'platform' ), '</td>';
		echo '<td>';

		if ( config_get( 'allow_freetext_in_profile_fields' ) == OFF ) {
			echo '<select name="platform"><option value=""></option>';
			print_platform_option_list( $tpl_bug->platform );
			echo '</select>';
		} else {
			projax_autocomplete( 'platform_get_with_prefix', 'platform', array( 'value' => $tpl_bug->platform, 'size' => '16', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
		}

		echo '</td>';
	} else {
		$t_spacer += 2;
	}

	if ( $tpl_show_os ) {
		# Operating System
		echo '<td class="category">', lang_get( 'os' ), '</td>';
		echo '<td>';

		if ( config_get( 'allow_freetext_in_profile_fields' ) == OFF ) {
			echo '<select name="os"><option value=""></option>';
			print_os_option_list( $tpl_bug->os );
			echo '</select>';
		} else {
			projax_autocomplete( 'os_get_with_prefix', 'os', array( 'value' => $tpl_bug->os, 'size' => '16', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
		}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -438,7 +438,7 @@
 			print_platform_option_list( $tpl_bug->platform );
 			echo '</select>';
 		} else {
-			projax_autocomplete( 'platform_get_with_prefix', 'platform', array( 'value' => $tpl_bug->platform, 'size' => '16', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
+			projax_autocomplete( 'platform_get_with_prefix', 'platform', array( 'value' => string_attribute( $tpl_bug->platform ), 'size' => '16', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
 		}
 
 		echo '</td>';
@@ -456,7 +456,7 @@
 			print_os_option_list( $tpl_bug->os );
 			echo '</select>';
 		} else {
-			projax_autocomplete( 'os_get_with_prefix', 'os', array( 'value' => $tpl_bug->os, 'size' => '16', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
+			projax_autocomplete( 'os_get_with_prefix', 'os', array( 'value' => string_attribute( $tpl_bug->os ), 'size' => '16', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
 		}
 
 		echo '</td>';
@@ -474,7 +474,7 @@
 			print_os_build_option_list( $tpl_bug->os_build );
 			echo '</select>';
 		} else {
-			projax_autocomplete( 'os_build_get_with_prefix', 'os_build', array( 'value' => $tpl_bug->os_build, 'size' => '16', 'maxlength' => '16', 'tabindex' => helper_get_tab_index_value() ) );
+			projax_autocomplete( 'os_build_get_with_prefix', 'os_build', array( 'value' => string_attribute( $tpl_bug->os_build ), 'size' => '16', 'maxlength' => '16', 'tabindex' => helper_get_tab_index_value() ) );
 		}
 
 		echo '</td>';
```
