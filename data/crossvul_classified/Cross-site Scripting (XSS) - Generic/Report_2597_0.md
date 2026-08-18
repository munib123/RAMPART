# CrossVul Fix Pair: Improper Encoding or Escaping of Output in php
**Pair ID:** 2597_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2597_0`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```php
Lines 117-157 of the vulnerable file.

	if ( is_string($msg_str) && strlen($msg_str) ) {
		$tm = date('Ymd:Hms') . ' ' . $msg_str . PHP_EOL;
		//
		$rslt = file_put_contents($dir.DS.$logfile, $tm, FILE_APPEND);
	} else {
		//
		$fnctn = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1]['function'];
		csv_edihist_log ('invalid message string '.$fnctn);
	}
	//
	return $rslt;  // number of characters written
}

/**
 * read the edi_history_log.txt file into an
 * html formatted ordered list
 *
 * @return string
 */
function csv_log_html($logname='') {
	$html_str = "<div class='filetext'>".PHP_EOL."<ol class='logview'>".PHP_EOL;
    $fp = csv_edih_basedir().DS.'log'.DS.$logname;
    if ( is_file($fp) ) {
		$fh = fopen( $fp, 'r');
		if ($fh !== FALSE) {
			while (($buffer = fgets($fh)) !== false) {
				$html_str .= "<li>".$buffer."</li>".PHP_EOL;
			}
			$html_str .= "</ol>".PHP_EOL."</div>".PHP_EOL;
			if (!feof($fh)) {
				$html_str .= "<p>Error in logfile: unexpected file ending</p>".PHP_EOL;
			}
			fclose($fh);
		} else {
			$html_str = "<p>Error: unable to open log file</p>".PHP_EOL;
		}
	}
	return $html_str;
}


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,6 +134,7 @@
  * @return string
  */
 function csv_log_html($logname='') {
+	check_file_dir_name($logname);
 	$html_str = "<div class='filetext'>".PHP_EOL."<ol class='logview'>".PHP_EOL;
     $fp = csv_edih_basedir().DS.'log'.DS.$logname;
     if ( is_file($fp) ) {
```
