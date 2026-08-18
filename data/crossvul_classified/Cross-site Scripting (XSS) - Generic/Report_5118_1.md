# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5118_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5118_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 56-96 of the vulnerable file.

$f_field_id	= gpc_get_int( 'field_id' );
$f_return	= strip_tags( gpc_get_string( 'return', 'manage_custom_field_page.php' ) );

custom_field_ensure_exists( $f_field_id );

require_js( 'manage_custom_field_edit_page.js' );

html_page_top();

print_manage_menu( 'manage_custom_field_edit_page.php' );

$t_definition = custom_field_get_definition( $f_field_id );
?>

<div id="manage-custom-field-update-div" class="form-container">
	<form id="manage-custom-field-update-form" method="post" action="manage_custom_field_update.php">
		<fieldset>
			<legend><span><?php echo lang_get( 'edit_custom_field_title' ) ?></span></legend>
			<?php echo form_security_field( 'manage_custom_field_update' ); ?>
			<input type="hidden" name="field_id" value="<?php echo $f_field_id ?>" />
			<input type="hidden" name="return" value="<?php echo $f_return ?>" />
			<div class="field-container">
				<label for="custom-field-name"><span><?php echo lang_get( 'custom_field_name' ) ?></span></label>
				<span class="input"><input type="text" id="custom-field-name" name="name" size="32" maxlength="64" value="<?php echo string_attribute( $t_definition['name'] ) ?>" /></span>
				<span class="label-style"></span>
			</div>
			<div class="field-container">
				<label for="custom-field-type"><span><?php echo lang_get( 'custom_field_type' ) ?></span></label>
				<span class="select">
					<select id="custom-field-type" name="type">
						<?php print_enum_string_option_list( 'custom_field_type', (int)$t_definition['type'] ) ?>
					</select>
				</span>
				<span class="label-style"></span>
			</div>
			<div class="field-container">
				<label for="custom-field-possible-values"><span><?php echo lang_get( 'custom_field_possible_values' ) ?></span></label>
				<span class="input"><input type="text" id="custom-field-possible-values" name="possible_values" size="100" value="<?php echo string_attribute( $t_definition['possible_values'] ) ?>" />
					<?php echo sprintf( lang_get( 'separate_list_items_by' ), '|' ) ?>
				</span>
				<span class="label-style"></span>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,7 +73,7 @@
 			<legend><span><?php echo lang_get( 'edit_custom_field_title' ) ?></span></legend>
 			<?php echo form_security_field( 'manage_custom_field_update' ); ?>
 			<input type="hidden" name="field_id" value="<?php echo $f_field_id ?>" />
-			<input type="hidden" name="return" value="<?php echo $f_return ?>" />
+			<input type="hidden" name="return" value="<?php echo string_attribute( $f_return ); ?>" />
 			<div class="field-container">
 				<label for="custom-field-name"><span><?php echo lang_get( 'custom_field_name' ) ?></span></label>
 				<span class="input"><input type="text" id="custom-field-name" name="name" size="32" maxlength="64" value="<?php echo string_attribute( $t_definition['name'] ) ?>" /></span>
```
