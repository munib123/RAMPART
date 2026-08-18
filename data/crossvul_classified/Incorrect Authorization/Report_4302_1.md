# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4302_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4302_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 93-133 of the vulnerable file.

		access_denied();
}
$t_result = db_query( $t_query, array( $c_file_id ) );
$t_row = db_fetch_array( $t_result );
if( false === $t_row ) {
	# Attachment not found
	error_parameters( $c_file_id );
	trigger_error( ERROR_FILE_NOT_FOUND, ERROR );
}
extract( $t_row, EXTR_PREFIX_ALL, 'v' );

if( $f_type == 'bug' ) {
	$t_project_id = bug_get_field( $v_bug_id, 'project_id' );
} else {
	$t_project_id = $v_project_id;
}

# Check access rights
switch( $f_type ) {
	case 'bug':
		if( !file_can_download_bug_attachments( $v_bug_id, (int)$v_user_id ) ) {
			access_denied();
		}
		break;
	case 'doc':
		# Check if project documentation feature is enabled.
		if( OFF == config_get( 'enable_project_documentation' ) ) {
			access_denied();
		}

		access_ensure_project_level( config_get( 'view_proj_doc_threshold' ), $v_project_id );
		break;
}

# throw away output buffer contents (and disable it) to protect download
while( @ob_end_clean() ) {
}

if( ini_get( 'zlib.output_compression' ) && function_exists( 'ini_set' ) ) {
	ini_set( 'zlib.output_compression', false );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,9 @@
 # Check access rights
 switch( $f_type ) {
 	case 'bug':
-		if( !file_can_download_bug_attachments( $v_bug_id, (int)$v_user_id ) ) {
+		if( !file_can_download_bug_attachments( $v_bug_id, $v_user_id )
+		|| !file_can_download_bugnote_attachments( $v_bugnote_id, $v_user_id )
+		) {
 			access_denied();
 		}
 		break;
```
