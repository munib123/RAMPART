# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 695_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `695_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 52-92 of the vulnerable file.

require_api( 'string_api.php' );
require_api( 'utility_api.php' );

form_security_validate( 'bug_report' );

$f_master_bug_id = gpc_get_int( 'm_id', 0 );
$f_rel_type = gpc_get_int( 'rel_type', BUG_REL_NONE );
$f_copy_notes_from_parent = gpc_get_bool( 'copy_notes_from_parent', false );
$f_copy_attachments_from_parent = gpc_get_bool( 'copy_attachments_from_parent', false );
$f_report_stay = gpc_get_bool( 'report_stay', false );

$t_clone_info = array(
	'master_issue_id' => $f_master_bug_id,
	'relationship_type' => $f_rel_type,
	'copy_notes' => $f_copy_notes_from_parent,
	'copy_files' => $f_copy_attachments_from_parent
);

if( $f_master_bug_id > 0 ) {
	bug_ensure_exists( $f_master_bug_id );
	if( bug_is_readonly( $f_master_bug_id ) ) {
		error_parameters( $f_master_bug_id );
		trigger_error( ERROR_BUG_READ_ONLY_ACTION_DENIED, ERROR );
	}
	$t_master_bug = bug_get( $f_master_bug_id, true );
	$t_project_id = $t_master_bug->project_id;
} else {
	$f_project_id = gpc_get_int( 'project_id' );
	$t_project_id = $f_project_id;
}

$t_issue = array(
	'project' => array( 'id' => $t_project_id ),
	'reporter' => array( 'id' => auth_get_current_user_id() ),
	'summary' => gpc_get_string( 'summary' ),
	'description' => gpc_get_string( 'description' ),
);

$t_tag_string = '';
$f_tag_select = gpc_get_int( 'tag_select', 0 );
if( $f_tag_select != 0 ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,6 +69,10 @@
 
 if( $f_master_bug_id > 0 ) {
 	bug_ensure_exists( $f_master_bug_id );
+
+	# User can view the master bug
+	access_ensure_bug_level( config_get( 'view_bug_threshold' ), $f_master_bug_id );
+
 	if( bug_is_readonly( $f_master_bug_id ) ) {
 		error_parameters( $f_master_bug_id );
 		trigger_error( ERROR_BUG_READ_ONLY_ACTION_DENIED, ERROR );
```
