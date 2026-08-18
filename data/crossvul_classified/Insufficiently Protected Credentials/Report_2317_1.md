# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 2317_1
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2317_1`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 25-65 of the vulnerable file.

	switch($_POST['do']) {
		case __('Backup', 'wp-dbmanager'):
			check_admin_referer('wp-dbmanager_backup');
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
			$gzip = intval($_POST['gzip']);
			if($gzip == 1) {
				$backup['filename'] = $backup['date'].'_-_'.DB_NAME.'.sql.gz';
				$backup['filepath'] = $backup['path'].'/'.$backup['filename'];
				$backup['command'] = $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' --add-drop-table --skip-lock-tables '.DB_NAME.' | gzip > '.$brace.$backup['filepath'].$brace;
			} else {
				$backup['filename'] = $backup['date'].'_-_'.DB_NAME.'.sql';
				$backup['filepath'] = $backup['path'].'/'.$backup['filename'];
				$backup['command'] = $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' --add-drop-table --skip-lock-tables '.DB_NAME.' > '.$brace.$backup['filepath'].$brace;
			}
			$error = execute_backup($backup['command']);
			if(!is_writable($backup['path'])) {
				$text = '<p style="color: red;">'.sprintf(__('Database Failed To Backup On \'%s\'. Backup Folder Not Writable.', 'wp-dbmanager'), $current_date).'</p>';
			} elseif(filesize($backup['filepath']) == 0) {
				unlink($backup['filepath']);
				$text = '<p style="color: red;">'.sprintf(__('Database Failed To Backup On \'%s\'. Backup File Size Is 0KB.', 'wp-dbmanager'), $current_date).'</p>';
			} elseif(!is_file($backup['filepath'])) {
				$text = '<p style="color: red;">'.sprintf(__('Database Failed To Backup On \'%s\'. Invalid Backup File Path.', 'wp-dbmanager'), $current_date).'</p>';
			} elseif($error) {
				$text = '<p style="color: red;">'.sprintf(__('Database Failed To Backup On \'%s\'.', 'wp-dbmanager'), $current_date).'</p>';
			} else {
				$text = '<p style="color: green;">'.sprintf(__('Database Backed Up Successfully On \'%s\'.', 'wp-dbmanager'), $current_date).'</p>';
			}
			break;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,11 +42,11 @@
 			if($gzip == 1) {
 				$backup['filename'] = $backup['date'].'_-_'.DB_NAME.'.sql.gz';
 				$backup['filepath'] = $backup['path'].'/'.$backup['filename'];
-				$backup['command'] = $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' --add-drop-table --skip-lock-tables '.DB_NAME.' | gzip > '.$brace.$backup['filepath'].$brace;
+				$backup['command'] = escapeshellcmd( $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' --add-drop-table --skip-lock-tables '.DB_NAME ).' | gzip > '.escapeshellcmd( $brace.$backup['filepath'].$brace );
 			} else {
 				$backup['filename'] = $backup['date'].'_-_'.DB_NAME.'.sql';
 				$backup['filepath'] = $backup['path'].'/'.$backup['filename'];
-				$backup['command'] = $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' --add-drop-table --skip-lock-tables '.DB_NAME.' > '.$brace.$backup['filepath'].$brace;
+				$backup['command'] = escapeshellcmd( $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].$backup['charset'].' --add-drop-table --skip-lock-tables '.DB_NAME ).' > '.escapeshellcmd( $brace.$backup['filepath'].$brace );
 			}
 			$error = execute_backup($backup['command']);
 			if(!is_writable($backup['path'])) {
```
