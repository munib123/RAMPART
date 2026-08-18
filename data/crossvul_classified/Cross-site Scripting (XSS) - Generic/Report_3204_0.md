# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3204_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3204_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 137-177 of the vulnerable file.

<h2><?php echo lang_get( $t_status_label . '_bug_title' ); ?></h2>
<?php
	if( $f_new_status >= $t_resolved ) {
		if( relationship_can_resolve_bug( $f_bug_id ) == false ) {
			echo '<div class="footer">';
			echo lang_get( 'relationship_warning_blocking_bugs_not_resolved_2' );
			echo '</div>';
		}
	}
?>

<form id="bug-change-status-form" name="bug_change_status_form" method="post" action="bug_update.php">

<fieldset>

	<?php echo form_security_field( 'bug_update' ) ?>

	<input type="hidden" name="bug_id" value="<?php echo $f_bug_id ?>" />
	<input type="hidden" name="status" value="<?php echo $f_new_status ?>" />
	<input type="hidden" name="last_updated" value="<?php echo $t_bug->last_updated ?>" />
	<input type="hidden" name="action_type" value="<?php echo $f_change_type; ?>" />

<?php
	$t_current_resolution = $t_bug->resolution;
	$t_bug_is_open = $t_current_resolution < $t_resolved;

	if( $f_new_status >= $t_resolved && ( $f_new_status < $t_closed || $t_bug_is_open ) ) {
?>
	<!-- Resolution -->
	<div class="field-container">
		<label for="resolution">
			<span><?php echo lang_get( 'resolution' ) ?></span>
		</label>
		<span class="select">
 			<select name="resolution">
<?php
				$t_resolution = $t_bug_is_open ? config_get( 'bug_resolution_fixed_threshold' ) : $t_current_resolution;

				$t_relationships = relationship_get_all_src( $f_bug_id );
				foreach( $t_relationships as $t_relationship ) {
					if( $t_relationship->type == BUG_DUPLICATE ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -154,7 +154,7 @@
 	<input type="hidden" name="bug_id" value="<?php echo $f_bug_id ?>" />
 	<input type="hidden" name="status" value="<?php echo $f_new_status ?>" />
 	<input type="hidden" name="last_updated" value="<?php echo $t_bug->last_updated ?>" />
-	<input type="hidden" name="action_type" value="<?php echo $f_change_type; ?>" />
+	<input type="hidden" name="action_type" value="<?php echo string_attribute( $f_change_type ); ?>" />
 
 <?php
 	$t_current_resolution = $t_bug->resolution;
```
