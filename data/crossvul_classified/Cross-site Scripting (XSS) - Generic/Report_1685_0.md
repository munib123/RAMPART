# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1685_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1685_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 210-250 of the vulnerable file.

				</td>
			</tr>
			<?php } ?>
			<tr>
				<th scope="row" valign="top">
					<label for="recaptcha"><?php _e('Use reCAPTCHA?', 'pmpro');?>:</label>
				</th>
				<td>
					<select id="recaptcha" name="recaptcha" onchange="pmpro_updateRecaptchaTRs();">
						<option value="0" <?php if(!$recaptcha) { ?>selected="selected"<?php } ?>><?php _e('No', 'pmpro');?></option>
						<option value="1" <?php if($recaptcha == 1) { ?>selected="selected"<?php } ?>><?php _e('Yes - Free memberships only.', 'pmpro');?></option>
						<option value="2" <?php if($recaptcha == 2) { ?>selected="selected"<?php } ?>><?php _e('Yes - All memberships.', 'pmpro');?></option>
					</select><br />
					<small><?php _e('A free reCAPTCHA key is required.', 'pmpro');?> <a href="https://www.google.com/recaptcha/admin/create"><?php _e('Click here to signup for reCAPTCHA', 'pmpro');?></a>.</small>
				</td>
			</tr>
			<tr id="recaptcha_tr" <?php if(!$recaptcha) { ?>style="display: none;"<?php } ?>>
				<th scope="row" valign="top">&nbsp;</th>
				<td>
					<label for="recaptcha_publickey"><?php _e('reCAPTCHA Public Key', 'pmpro');?>:</label>
					<input type="text" name="recaptcha_publickey" size="60" value="<?php echo $recaptcha_publickey?>" />
					<br /><br />
					<label for="recaptcha_privatekey"><?php _e('reCAPTCHA Private Key', 'pmpro');?>:</label>
					<input type="text" name="recaptcha_privatekey" size="60" value="<?php echo $recaptcha_privatekey?>" />
				</td>
			</tr>
			<tr>
				<th scope="row" valign="top">
					<label for="tospage"><?php _e('Require Terms of Service on signups?', 'pmpro');?></label>
				</th>
				<td>
					<?php
						wp_dropdown_pages(array("name"=>"tospage", "show_option_none"=>"No", "selected"=>$tospage));
					?>
					<br />
					<small><?php _e('If yes, create a WordPress page containing your TOS agreement and assign it using the dropdown above.', 'pmpro');?></small>
				</td>
			</tr>

			<?php /*
			<tr>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -227,10 +227,10 @@
 				<th scope="row" valign="top">&nbsp;</th>
 				<td>
 					<label for="recaptcha_publickey"><?php _e('reCAPTCHA Public Key', 'pmpro');?>:</label>
-					<input type="text" name="recaptcha_publickey" size="60" value="<?php echo $recaptcha_publickey?>" />
+					<input type="text" name="recaptcha_publickey" size="60" value="<?php echo esc_attr($recaptcha_publickey);?>" />
 					<br /><br />
 					<label for="recaptcha_privatekey"><?php _e('reCAPTCHA Private Key', 'pmpro');?>:</label>
-					<input type="text" name="recaptcha_privatekey" size="60" value="<?php echo $recaptcha_privatekey?>" />
+					<input type="text" name="recaptcha_privatekey" size="60" value="<?php echo esc_attr($recaptcha_privatekey);?>" />
 				</td>
 			</tr>
 			<tr>
@@ -296,14 +296,14 @@
                             <input id="<?php _e($field['field_name'], 'pmpro'); ?>"
                                    name="<?php _e($field['field_name'], 'pmpro'); ?>"
                                    type="<?php _e($field['field_type'], 'pmpro'); ?>"
-                                   value="<?php echo pmpro_getOption($field['field_name']); ?> ">
+                                   value="<?php echo esc_attr(pmpro_getOption($field['field_name'])); ?> ">
                             <?php
                             break;
                         case 'textarea':
                             ?>
                             <textarea id="<?php _e($field['field_name'], 'pmpro'); ?>"
                                       name="<?php _e($field['field_name'], 'pmpro'); ?>">
-                                <?php echo pmpro_getOption($field['field_name']); ?>
+                                <?php echo esc_textarea(pmpro_getOption($field['field_name'])); ?>
                             </textarea>
                             <?php
                             break;
```
