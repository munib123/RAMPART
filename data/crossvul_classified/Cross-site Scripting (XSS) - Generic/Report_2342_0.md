# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2342_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2342_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 463-503 of the vulnerable file.

		<?php echo lang_get( 'project_name' ) ?>
	</td>
	<td>
		<select name="project_id">
			<option value="<?php echo ALL_PROJECTS; ?>"
				<?php check_selected( $t_edit_project_id, ALL_PROJECTS ); ?>>
				<?php echo lang_get( 'all_projects' ); ?>
			</option>
			<?php print_project_option_list( $t_edit_project_id, false ) ?>
		</select>
	</td>
</tr>

<!-- Config option name -->
<tr <?php echo helper_alternate_class() ?> valign="top">
	<td>
		<?php echo lang_get( 'configuration_option' ) ?>
	</td>
	<td>
		<input type="text" name="config_option"
			value="<?php echo $t_edit_option; ?>"
			size="64" maxlength="64" />
	</td>
</tr>

<!-- Option type -->
<tr <?php echo helper_alternate_class() ?> valign="top">
	<td>
		<?php echo lang_get( 'configuration_option_type' ) ?>
	</td>
	<td>
		<select name="type">
			<?php print_option_list_from_array( $t_config_types, $t_edit_type ); ?>
		</select>
	</td>
</tr>

<!-- Option Value -->
<tr <?php echo helper_alternate_class() ?> valign="top">
	<td>
		<?php echo lang_get( 'configuration_option_value' ) ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -480,7 +480,7 @@
 	</td>
 	<td>
 		<input type="text" name="config_option"
-			value="<?php echo $t_edit_option; ?>"
+			value="<?php echo string_attribute( $t_edit_option ); ?>"
 			size="64" maxlength="64" />
 	</td>
 </tr>
```
