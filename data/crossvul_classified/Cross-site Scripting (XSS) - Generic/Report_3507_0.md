# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3507_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3507_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 274-314 of the vulnerable file.

		<td colspan="2" class="none">
			<?php if( ON == config_get( 'use_javascript' ) ) { ?>
				<?php collapse_open( 'profile' ); collapse_icon('profile'); ?>
				<?php echo lang_get( 'or_fill_in' ); ?>
			<table class="width90" cellspacing="0">
					<?php } else { ?>
						<?php echo lang_get( 'or_fill_in' ); ?>
					<?php } ?>
					<tr <?php echo helper_alternate_class() ?>>
						<td class="category">
							<?php echo lang_get( 'platform' ) ?>
						</td>
						<td>
							<?php if ( config_get( 'allow_freetext_in_profile_fields' ) == OFF ) { ?>
							<select name="platform">
								<option value=""></option>
								<?php print_platform_option_list( $f_platform ); ?>
							</select>
							<?php
								} else {
									projax_autocomplete( 'platform_get_with_prefix', 'platform', array( 'value' => $f_platform, 'size' => '32', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
								}
							?>
						</td>
					</tr>
					<tr <?php echo helper_alternate_class() ?>>
						<td class="category">
							<?php echo lang_get( 'os' ) ?>
						</td>
						<td>
							<?php if ( config_get( 'allow_freetext_in_profile_fields' ) == OFF ) { ?>
							<select name="os">
								<option value=""></option>
								<?php print_os_option_list( $f_os ); ?>
							</select>
							<?php
								} else {
									projax_autocomplete( 'os_get_with_prefix', 'os', array( 'value' => $f_os, 'size' => '32', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
								}
							?>
						</td>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -291,7 +291,7 @@
 							</select>
 							<?php
 								} else {
-									projax_autocomplete( 'platform_get_with_prefix', 'platform', array( 'value' => $f_platform, 'size' => '32', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
+									projax_autocomplete( 'platform_get_with_prefix', 'platform', array( 'value' => string_attribute( $f_platform ), 'size' => '32', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
 								}
 							?>
 						</td>
@@ -308,7 +308,7 @@
 							</select>
 							<?php
 								} else {
-									projax_autocomplete( 'os_get_with_prefix', 'os', array( 'value' => $f_os, 'size' => '32', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
+									projax_autocomplete( 'os_get_with_prefix', 'os', array( 'value' => string_attribute( $f_os ), 'size' => '32', 'maxlength' => '32', 'tabindex' => helper_get_tab_index_value() ) );
 								}
 							?>
 						</td>
@@ -327,7 +327,7 @@
 								</select>
 							<?php
 								} else {
-									projax_autocomplete( 'os_build_get_with_prefix', 'os_build', array( 'value' => $f_os_build, 'size' => '16', 'maxlength' => '16', 'tabindex' => helper_get_tab_index_value() ) );
+									projax_autocomplete( 'os_build_get_with_prefix', 'os_build', array( 'value' => string_attribute( $f_os_build ), 'size' => '16', 'maxlength' => '16', 'tabindex' => helper_get_tab_index_value() ) );
 								}
 							?>
 						</td>
```
