# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 2317_2
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2317_2`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 27-67 of the vulnerable file.

	$text = '';

	// Decide What To Do
	switch($_POST['do']) {
		case __('Restore', 'wp-dbmanager'):
			if(!empty($database_file)) {
				$brace = (substr(PHP_OS, 0, 3) == 'WIN') ? '"' : '';
				$backup['host'] = DB_HOST;
				$backup['port'] = '';
				$backup['sock'] = '';
				if(strpos(DB_HOST, ':') !== false) {
					$db_host = explode(':', DB_HOST);
					$backup['host'] = $db_host[0];
					if(intval($db_host[1]) != 0) {
						$backup['port'] = ' --port="'.intval($db_host[1]).'"';
					} else {
						$backup['sock'] = ' --socket="'.$db_host[1].'"';
					}
				}
				if(stristr($database_file, '.gz')) {
					$backup['command'] = 'gunzip < '.$brace.$backup['path'].'/'.$database_file.$brace.' | '.$brace.$backup['mysqlpath'].$brace.' --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' '.DB_NAME;
				} else {
					$backup['command'] = $brace.$backup['mysqlpath'].$brace.' --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' '.DB_NAME.' < '.$brace.$backup['path'].'/'.$database_file.$brace;
				}
				if( realpath( $backup['path'] ) === false ) {
					$text = '<p style="color: red;">' . sprintf(__('%s is not a valid backup path', 'wp-dbmanager'), stripslashes( $backup['path'] ) ) . '</p>';
				} else if( dbmanager_is_valid_path( $backup['mysqlpath'] ) === 0 ) {
					$text = '<p style="color: red;">' . sprintf(__('%s is not a valid mysql path', 'wp-dbmanager'), stripslashes( $backup['mysqlpath'] ) ) . '</p>';
				} else {
					passthru( $backup['command'], $error );
				}
				if($error) {
					$text = '<p style="color: red;">'.sprintf(__('Database On \'%s\' Failed To Restore', 'wp-dbmanager'), $nice_file_date).'</p>';
				} else {
					$text = '<p style="color: green;">'.sprintf(__('Database On \'%s\' Restored Successfully', 'wp-dbmanager'), $nice_file_date).'</p>';
				}
			} else {
				$text = '<p style="color: red;">'.__('No Backup Database File Selected', 'wp-dbmanager').'</p>';
			}
			break;
		case __('E-Mail', 'wp-dbmanager'):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,9 +44,9 @@
 					}
 				}
 				if(stristr($database_file, '.gz')) {
-					$backup['command'] = 'gunzip < '.$brace.$backup['path'].'/'.$database_file.$brace.' | '.$brace.$backup['mysqlpath'].$brace.' --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' '.DB_NAME;
+					$backup['command'] = 'gunzip < '.escapeshellcmd( $brace.$backup['path'].'/'.$database_file.$brace ).' | '.escapeshellcmd( $brace.$backup['mysqlpath'].$brace.' --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' '.DB_NAME );
 				} else {
-					$backup['command'] = $brace.$backup['mysqlpath'].$brace.' --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' '.DB_NAME.' < '.$brace.$backup['path'].'/'.$database_file.$brace;
+					$backup['command'] = escapeshellcmd( $brace.$backup['mysqlpath'].$brace.' --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' '.DB_NAME ).' < '.escapeshellcmd( $brace.$backup['path'].'/'.$database_file.$brace );
 				}
 				if( realpath( $backup['path'] ) === false ) {
 					$text = '<p style="color: red;">' . sprintf(__('%s is not a valid backup path', 'wp-dbmanager'), stripslashes( $backup['path'] ) ) . '</p>';
```
