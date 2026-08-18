# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2595_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2595_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 404-444 of the vulnerable file.

	</td>
	<?php
		$t_db_open = false;
	$g_db = ADONewConnection( $f_db_type );
	$t_result = @$g_db->Connect( $f_hostname, $f_admin_username, $f_admin_password );

	if( $t_result ) {
		# due to a bug in ADODB, this call prompts warnings, hence the @
		# the check only works on mysql if the database is open
		$t_version_info = @$g_db->ServerInfo();

		# check if db exists for the admin
		$t_result = @$g_db->Connect( $f_hostname, $f_admin_username, $f_admin_password, $f_database_name );
		if( $t_result ) {
			$t_db_open = true;
			$f_db_exists = true;
		}

		print_test_result( GOOD );
	} else {
		print_test_result( BAD, true, 'Does administrative user have access to the database? ( ' . db_error_msg() . ' )' );
		$t_version_info = null;
	}
	?>
</tr>
<?php
	if( $f_db_exists ) {
		?>
<tr>
	<td>
		Attempting to connect to database as user
	</td>
	<?php
		$g_db = ADONewConnection( $f_db_type );
		$t_result = @$g_db->Connect( $f_hostname, $f_db_username, $f_db_password, $f_database_name );

		if( $t_result == true ) {
			$t_db_open = true;
			print_test_result( GOOD );
		} else {
			print_test_result( BAD, false, 'Database user doesn\'t have access to the database ( ' . db_error_msg() . ' )' );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -421,7 +421,11 @@
 
 		print_test_result( GOOD );
 	} else {
-		print_test_result( BAD, true, 'Does administrative user have access to the database? ( ' . db_error_msg() . ' )' );
+		print_test_result(
+			BAD,
+			true,
+			'Does administrative user have access to the database? ( ' . string_attribute( db_error_msg() ) . ' )'
+		);
 		$t_version_info = null;
 	}
 	?>
@@ -441,7 +445,11 @@
 			$t_db_open = true;
 			print_test_result( GOOD );
 		} else {
-			print_test_result( BAD, false, 'Database user doesn\'t have access to the database ( ' . db_error_msg() . ' )' );
+			print_test_result(
+				BAD,
+				false,
+				'Database user doesn\'t have access to the database ( ' . string_attribute( db_error_msg() ) . ' )'
+			);
 		}
 		?>
 </tr>
@@ -793,9 +801,17 @@
 				}
 
 				if( $t_db_exists ) {
-					print_test_result( BAD, false, 'Database already exists? ( ' . db_error_msg() . ' )' );
+					print_test_result(
+						BAD,
+						false,
+						'Database already exists? ( ' . string_attribute( db_error_msg() ) . ' )'
+					);
 				} else {
-					print_test_result( BAD, true, 'Does administrative user have access to create the database? ( ' . db_error_msg() . ' )' );
+					print_test_result(
+						BAD,
+						true,
+						'Does administrative user have access to create the database? ( ' . string_attribute( db_error_msg() ) . ' )'
+					);
 					$t_install_state--; # db creation failed, allow user to re-enter user/password info
 				}
 			}
@@ -817,7 +833,11 @@
 		if( $t_result == true ) {
 			print_test_result( GOOD );
 		} else {
-			print_test_result( BAD, false, 'Database user doesn\'t have access to the database ( ' . db_error_msg() . ' )' );
+			print_test_result(
+				BAD,
+				false,
+				'Database user doesn\'t have access to the database ( ' . string_attribute( db_error_msg() ) . ' )'
+			);
 		}
 		$g_db->Close();
 	?>
@@ -1217,7 +1237,11 @@
 	if( $t_result == true ) {
 		print_test_result( GOOD );
 	} else {
-		print_test_result( BAD, false, 'Database user does not have access to the database ( ' . db_error_msg() . ' )' );
+		print_test_result(
+			BAD,
+			false,
+			'Database user does not have access to the database ( ' . string_attribute( db_error_msg() ) . ' )'
+		);
 	}
 	?>
 </tr>
@@ -1232,7 +1256,11 @@
 	if( $t_result != false ) {
 		print_test_result( GOOD );
 	} else {
-		print_test_result( BAD, true, 'Database user does not have SELECT access to the database ( ' . db_error_msg() . ' )' );
+		print_test_result(
+			BAD,
+			true,
+			'Database user does not have SELECT access to the database ( ' . string_attribute( db_error_msg() ) . ' )'
+		);
 	}
 	?>
 </tr>
@@ -1247,7 +1275,11 @@
 	if( $t_result != false ) {
 		print_test_result( GOOD );
 	} else {
-		print_test_result( BAD, true, 'Database user does not have INSERT access to the database ( ' . db_error_msg() . ' )' );
+		print_test_result(
+			BAD,
+			true,
+			'Database user does not have INSERT access to the database ( ' . string_attribute( db_error_msg() ) . ' )'
+		);
 	}
 	?>
 </tr>
@@ -1262,7 +1294,11 @@
 	if( $t_result != false ) {
 		print_test_result( GOOD );
 	} else {
-		print_test_result( BAD, true, 'Database user does not have UPDATE access to the database ( ' . db_error_msg() . ' )' );
+		print_test_result(
+			BAD,
+			true,
+			'Database user does not have UPDATE access to the database ( ' . string_attribute( db_error_msg() ) . ' )'
+		);
 	}
 	?>
 </tr>
@@ -1277,7 +1313,11 @@
 	if( $t_result != false ) {
 		print_test_result( GOOD );
 	} else {
-		print_test_result( BAD, true, 'Database user does not have DELETE access to the database ( ' . db_error_msg() . ' )' );
+		print_test_result(
+			BAD,
+			true,
+			'Database user does not have DELETE access to the database ( ' . string_attribute( db_error_msg() ) . ' )'
+		);
 	}
 	?>
 </tr>
```
