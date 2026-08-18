# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3599_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3599_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 38-79 of the vulnerable file.

 * MantisBT Core API's
 */
require_once( 'core.php' );
require_api( 'access_api.php' );
require_api( 'authentication_api.php' );
require_api( 'category_api.php' );
require_api( 'config_api.php' );
require_api( 'form_api.php' );
require_api( 'gpc_api.php' );
require_api( 'helper_api.php' );
require_api( 'html_api.php' );
require_api( 'lang_api.php' );
require_api( 'print_api.php' );
require_api( 'string_api.php' );

auth_reauthenticate();

$f_category_id		= gpc_get_int( 'id' );
$f_project_id		= gpc_get_int( 'project_id' );

access_ensure_project_level( config_get( 'manage_project_threshold' ), $f_project_id );

$t_row = category_get_row( $f_category_id );
$t_assigned_to = $t_row['user_id'];
$t_project_id = $t_row['project_id'];
$t_name = $t_row['name'];

html_page_top();

print_manage_menu( 'manage_proj_cat_edit_page.php' ); ?>

<div id="manage-proj-category-update-div" class="form-container">
	<form id="manage-proj-category-update-form" method="post" action="manage_proj_cat_update.php">
		<fieldset>
			<legend><span><?php echo lang_get( 'edit_project_category_title' ) ?></span></legend>
			<?php echo form_security_field( 'manage_proj_cat_update' ) ?>
			<input type="hidden" name="project_id" value="<?php echo $f_project_id ?>"/>
			<input type="hidden" name="category_id" value="<?php echo string_attribute( $f_category_id ) ?>" />
			<div class="field-container <?php echo helper_alternate_class_no_attribute(); ?>">
				<label for="proj-category-name"><span><?php echo lang_get( 'category' ) ?></span></label>
				<span class="input"><input type="text" id="proj-category-name" name="name" size="32" maxlength="128" value="<?php echo string_attribute( $t_name ) ?>" /></span>
				<span class="label-style"></span>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,12 +55,12 @@
 $f_category_id		= gpc_get_int( 'id' );
 $f_project_id		= gpc_get_int( 'project_id' );
 
-access_ensure_project_level( config_get( 'manage_project_threshold' ), $f_project_id );
-
 $t_row = category_get_row( $f_category_id );
 $t_assigned_to = $t_row['user_id'];
 $t_project_id = $t_row['project_id'];
 $t_name = $t_row['name'];
+
+access_ensure_project_level( config_get( 'manage_project_threshold' ), $t_project_id );
 
 html_page_top();
 
```
