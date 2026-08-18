# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 3238_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3238_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 363-403 of the vulnerable file.

	 * We do this in order to have some of the info about the current doc throughout the
	 * loading process
	 *
	 * @since 1.0-beta
	 * @deprecated No longer used since 1.2
	 */
	function do_query() {
		_deprecated_function( __METHOD__, '1.2' );
	}

	/**
	 * Catches page loads, determines what to do, and sends users on their merry way
	 *
	 * @since 1.0-beta
	 * @todo This needs a ton of cleanup
	 */
	function catch_page_load() {
		global $bp;

		if ( !empty( $_POST['doc-edit-submit'] ) ) {

			check_admin_referer( 'bp_docs_save' );

			$this_doc = new BP_Docs_Query;
			$result = $this_doc->save();

			bp_core_add_message( $result['message'], $result['message_type'] );
			bp_core_redirect( trailingslashit( $result['redirect_url'] ) );
		}

		if ( !empty( $_POST['docs-filter-submit'] ) ) {
			$this->handle_filters();
		}

		// If this is the edit screen, ensure that the user can edit the
		// doc before querying, and redirect if necessary
		if ( bp_docs_is_doc_edit() ) {
			if ( current_user_can( 'bp_docs_edit' ) ) {
				$doc = bp_docs_get_current_doc();

				// The user can edit, so we check for edit locks
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -380,6 +380,14 @@
 		global $bp;
 
 		if ( !empty( $_POST['doc-edit-submit'] ) ) {
+
+			// Existing Docs have a more specific permission check.
+			$doc = bp_docs_get_current_doc();
+			if ( $doc && ! current_user_can( 'bp_docs_edit', $doc->ID ) ) {
+				return;
+			} elseif ( ! $doc && ! current_user_can( 'bp_docs_create' ) ) {
+				return;
+			}
 
 			check_admin_referer( 'bp_docs_save' );
 
```
