# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4890_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4890_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 882-922 of the vulnerable file.

		}
		?>
		<div id="major-publishing-actions">
			<?php if ( 'post.php' == $pagenow && $current_status_id != 'sf_closed' ) : ?>
				<div id="delete-action">
					<?php submit_button( $close_ticket_label, '', 'close-ticket-submit', false, array( 'id' => 'close-ticket-submit' ) ); ?>
				</div>
			<?php endif; ?>
			<div id="publishing-action">
				<?php submit_button( $submit_text, 'save-button primary', 'update-ticket', false ); ?>
			</div>
			<div class="clear"></div>
		</div>
	<?php
	}

	/**
	 * A box that appears at the top
	 */
	public function meta_box_subject() {

		$placeholder = __( 'What is your conversation about?', 'supportflow' );
		echo '<h4>' . __( 'Subject', 'supportflow' ) . '</h4>';
		echo '<input type="text" id="subject" name="post_title" class="sf_autosave" placeholder="' . $placeholder . '" value="' . get_the_title() . '" autocomplete="off" />';
		echo '<p class="description">' . __( 'Please describe what this ticket is about in several words', 'supportflow' ) . '</p>';

	}

	/**
	 * Add a form element where the user can change the customers
	 */
	public function meta_box_customers() {

		$placeholder = __( 'Who are you starting a conversation with?', 'supportflow' );
		if ( 'draft' == get_post_status( get_the_ID() ) ) {
			$customers_string = get_post_meta( get_the_ID(), '_sf_autosave_customers', true );
		} else {
			$customers        = SupportFlow()->get_ticket_customers( get_the_ID(), array( 'fields' => 'emails' ) );
			$customers_string = implode( ', ', $customers );
			$customers_string .= empty( $customers_string ) ? '' : ', ';
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -899,12 +899,25 @@
 	 * A box that appears at the top
 	 */
 	public function meta_box_subject() {
-
-		$placeholder = __( 'What is your conversation about?', 'supportflow' );
-		echo '<h4>' . __( 'Subject', 'supportflow' ) . '</h4>';
-		echo '<input type="text" id="subject" name="post_title" class="sf_autosave" placeholder="' . $placeholder . '" value="' . get_the_title() . '" autocomplete="off" />';
-		echo '<p class="description">' . __( 'Please describe what this ticket is about in several words', 'supportflow' ) . '</p>';
-
+		?>
+
+		<h4><?php _e( 'Subject', 'supportflow' ); ?></h4>
+
+		<input
+			type="text"
+			id="subject"
+			name="post_title"
+			class="sf_autosave"
+			placeholder="<?php _e( 'What is your conversation about?', 'supportflow' ); ?>"
+			value="<?php echo esc_attr( get_the_title() ); ?>"
+			autocomplete="off"
+		/>
+
+		<p class="description">
+			<?php _e( 'Please describe what this ticket is about in several words', 'supportflow' ) ?>
+		</p>
+
+		<?php
 	}
 
 	/**
```
