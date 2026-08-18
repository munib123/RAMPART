# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4293_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4293_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 450-490 of the vulnerable file.

function cfdef_input_textbox( array $p_field_def, $p_custom_field_value, $p_required = '' ) {
	echo '<input ', helper_get_tab_index(), ' type="text" id="custom_field_', $p_field_def['id']
			, '" name="custom_field_', $p_field_def['id'], '" ', $p_required;
	if( $p_field_def['length_max'] > 0 ) {
		echo ' maxlength="' . $p_field_def['length_max'] . '"'
				, ' size="' .  min( 80, $p_field_def['length_max'] ) . '"';
	} else {
		echo ' maxlength="255" size="80"';
	}
	if( !empty( $p_field_def['valid_regexp'] ) ) {
		# the custom field regex is evaluated with preg_match and looks for a partial match in the string
		# however, the html property is matched for the whole string.
		# unless we have explicit start and end tokens, adapt the html regex to allow a substring match.
		$t_cf_regex = $p_field_def['valid_regexp'];
		if( substr( $t_cf_regex, 0, 1 ) != '^' ) {
			$t_cf_regex = '.*' . $t_cf_regex;
		}
		if( substr( $t_cf_regex, -1 ) != '$' ) {
			$t_cf_regex .= '.*';
		}
		echo ' pattern="' . $t_cf_regex . '"';
	}
	echo ' value="' . string_attribute( $p_custom_field_value ) .'" />';
}

/**
 * print_custom_field_input
 * @param array $p_field_def          Custom field definition.
 * @param mixed $p_custom_field_value Custom field value.
 * @param string $p_required          The "required" attribute to add to the field
 * @return void
 */
function cfdef_input_textarea( array $p_field_def, $p_custom_field_value, $p_required = '' ) {
	echo '<textarea class="form-control" ', helper_get_tab_index(), ' id="custom_field_' . $p_field_def['id']
			, '" name="custom_field_', $p_field_def['id'], '"', $p_required;
	if( $p_field_def['length_max'] > 0 ) {
		echo ' maxlength="', $p_field_def['length_max'], '"';
	}
	echo ' cols="70" rows="8">', $p_custom_field_value, '</textarea>';
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -467,7 +467,7 @@
 		if( substr( $t_cf_regex, -1 ) != '$' ) {
 			$t_cf_regex .= '.*';
 		}
-		echo ' pattern="' . $t_cf_regex . '"';
+		echo ' pattern="' . string_attribute( $t_cf_regex ) . '"';
 	}
 	echo ' value="' . string_attribute( $p_custom_field_value ) .'" />';
 }
```
