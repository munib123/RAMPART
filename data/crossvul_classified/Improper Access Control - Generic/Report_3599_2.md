# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3599_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3599_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 147-187 of the vulnerable file.

			if ( 0 < count( $t_projects ) || 0 < count( $t_subprojects ) ) {
				array_unshift( $t_stack, $t_projects );
			}

			if ( 0 < count( $t_subprojects ) ) {
				$t_full_projects = array();
				foreach ( $t_subprojects as $t_project_id ) {
					$t_full_projects[] = project_get_row( $t_project_id );
				}
				$t_subprojects = multi_sort( $t_full_projects, $f_sort, $t_direction );
				array_unshift( $t_stack, $t_subprojects );
			}
		} ?>
	</table>
</div>

<div id="categories" class="form-container">
	<h2><?php echo lang_get( 'global_categories' ) ?></h2>
	<table cellspacing="1" cellpadding="5" border="1"><?php
		$t_categories = category_get_all_rows( ALL_PROJECTS );
		if ( count( $t_categories ) > 0 ) { ?>
		<tr class="row-category">
			<td><?php echo lang_get( 'category' ) ?></td>
			<td><?php echo lang_get( 'assign_to' ) ?></td>
			<td class="center"><?php echo lang_get( 'actions' ) ?></td>
		</tr><?php
		}

	foreach ( $t_categories as $t_category ) {
		$t_id = $t_category['id'];
	?>
		<tr <?php echo helper_alternate_class() ?>>
			<td><?php echo string_display( category_full_name( $t_id, false ) )  ?></td>
			<td><?php echo prepare_user_name( $t_category['user_id'] ) ?></td>
			<td class="center">
				<?php
					$t_id = urlencode( $t_id );
					$t_project_id = urlencode( ALL_PROJECTS );

					print_button( "manage_proj_cat_edit_page.php?id=$t_id&project_id=$t_project_id", lang_get( 'edit_link' ) );
					echo '&#160;';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -164,20 +164,25 @@
 	<h2><?php echo lang_get( 'global_categories' ) ?></h2>
 	<table cellspacing="1" cellpadding="5" border="1"><?php
 		$t_categories = category_get_all_rows( ALL_PROJECTS );
+		$t_can_update_global_cat = access_has_global_level( config_get( 'manage_site_threshold' ) );
+
 		if ( count( $t_categories ) > 0 ) { ?>
 		<tr class="row-category">
 			<td><?php echo lang_get( 'category' ) ?></td>
 			<td><?php echo lang_get( 'assign_to' ) ?></td>
+			<?php if( $t_can_update_global_cat ) { ?>
 			<td class="center"><?php echo lang_get( 'actions' ) ?></td>
+			<?php } ?>
 		</tr><?php
 		}
 
-	foreach ( $t_categories as $t_category ) {
+	foreach( $t_categories as $t_category ) {
 		$t_id = $t_category['id'];
 	?>
 		<tr <?php echo helper_alternate_class() ?>>
 			<td><?php echo string_display( category_full_name( $t_id, false ) )  ?></td>
 			<td><?php echo prepare_user_name( $t_category['user_id'] ) ?></td>
+			<?php if( $t_can_update_global_cat ) { ?>
 			<td class="center">
 				<?php
 					$t_id = urlencode( $t_id );
@@ -188,10 +193,12 @@
 					print_button( "manage_proj_cat_delete.php?id=$t_id&project_id=$t_project_id", lang_get( 'delete_link' ) );
 				?>
 			</td>
+			<?php } ?>
 		</tr><?php
 	} # end for loop ?>
 	</table>
 
+<?php if( $t_can_update_global_cat ) { ?>
 	<form method="post" action="manage_proj_cat_add.php">
 		<fieldset>
 			<?php echo form_security_field( 'manage_proj_cat_add' ) ?>
@@ -200,6 +207,7 @@
 			<input type="submit" class="button" value="<?php echo lang_get( 'add_category_button' ) ?>" />
 		</fieldset>
 	</form>
+<?php } ?>
 </div>
 
 <?php
```
