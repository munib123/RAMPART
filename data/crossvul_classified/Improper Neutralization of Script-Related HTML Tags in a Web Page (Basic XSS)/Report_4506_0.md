# CrossVul Fix Pair: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) in php
**Pair ID:** 4506_0
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**CWE:** CWE-80
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4506_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - This may allow such characters to be treated as control characters, which are executed client-side in the context of the user's session.

## Vulnerable Code
```php
Lines 388-428 of the vulnerable file.

	$can_resume  = current_user_can( 'resume_themes' );
	$can_delete  = current_user_can( 'delete_themes' );
	$can_install = current_user_can( 'install_themes' );
	?>
<table>
	<tr>
		<th><?php _ex( 'Name', 'theme name' ); ?></th>
		<th><?php _e( 'Description' ); ?></th>
		<?php if ( $can_resume ) { ?>
			<td></td>
		<?php } ?>
		<?php if ( $can_delete ) { ?>
			<td></td>
		<?php } ?>
		<?php if ( $can_install ) { ?>
			<td></td>
		<?php } ?>
	</tr>
	<?php foreach ( $broken_themes as $broken_theme ) : ?>
		<tr>
			<td><?php echo $broken_theme->get( 'Name' ) ? $broken_theme->display( 'Name' ) : $broken_theme->get_stylesheet(); ?></td>
			<td><?php echo $broken_theme->errors()->get_error_message(); ?></td>
			<?php
			if ( $can_resume ) {
				if ( 'theme_paused' === $broken_theme->errors()->get_error_code() ) {
					$stylesheet = $broken_theme->get_stylesheet();
					$resume_url = add_query_arg(
						array(
							'action'     => 'resume',
							'stylesheet' => urlencode( $stylesheet ),
						),
						admin_url( 'themes.php' )
					);
					$resume_url = wp_nonce_url( $resume_url, 'resume-theme_' . $stylesheet );
					?>
					<td><a href="<?php echo esc_url( $resume_url ); ?>" class="button resume-theme"><?php _e( 'Resume' ); ?></a></td>
					<?php
				} else {
					?>
					<td></td>
					<?php
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -405,7 +405,7 @@
 	</tr>
 	<?php foreach ( $broken_themes as $broken_theme ) : ?>
 		<tr>
-			<td><?php echo $broken_theme->get( 'Name' ) ? $broken_theme->display( 'Name' ) : $broken_theme->get_stylesheet(); ?></td>
+			<td><?php echo $broken_theme->get( 'Name' ) ? $broken_theme->display( 'Name' ) : esc_html( $broken_theme->get_stylesheet() ); ?></td>
 			<td><?php echo $broken_theme->errors()->get_error_message(); ?></td>
 			<?php
 			if ( $can_resume ) {
```
