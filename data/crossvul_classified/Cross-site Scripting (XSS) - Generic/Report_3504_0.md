# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3504_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3504_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 95-135 of the vulnerable file.

			  || ( ':443' == $t_port && 'https' == $t_protocol )) {
				$t_port = '';
			}
		} else {
			$t_port = '';
		}

		if ( isset( $_SERVER['HTTP_X_FORWARDED_HOST'] ) ) { // Support ProxyPass
			$t_hosts = explode( ',', $_SERVER['HTTP_X_FORWARDED_HOST'] );
			$t_host = $t_hosts[0];
		} else if ( isset( $_SERVER['HTTP_HOST'] ) ) {
			$t_host = $_SERVER['HTTP_HOST'];
		} else if ( isset( $_SERVER['SERVER_NAME'] ) ) {
			$t_host = $_SERVER['SERVER_NAME'] . $t_port;
		} else if ( isset( $_SERVER['SERVER_ADDR'] ) ) {
			$t_host = $_SERVER['SERVER_ADDR'] . $t_port;
		} else {
			$t_host = 'localhost';
		}

		$t_path = str_replace( basename( $_SERVER['PHP_SELF'] ), '', $_SERVER['PHP_SELF'] );
		$t_path = basename( $t_path ) == "admin" ? dirname( $t_path ) . '/' : $t_path;
		$t_path = basename( $t_path ) == "soap" ? dirname( dirname( $t_path ) ) . '/' : $t_path;
		

		$t_url	= $t_protocol . '://' . $t_host . $t_path;

	} else {
		$t_path = '';
		$t_host = '';
		$t_protocol = '';
	}

	/**
	 * path to your installation as seen from the web browser
	 * requires trailing /
	 * @global string $g_path
	 */
	$g_path	= isset( $t_url ) ? $t_url : 'http://localhost/mantisbt/';

	/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -112,10 +112,15 @@
 			$t_host = 'localhost';
 		}
 
-		$t_path = str_replace( basename( $_SERVER['PHP_SELF'] ), '', $_SERVER['PHP_SELF'] );
+		$t_self = $_SERVER['SCRIPT_NAME'];
+		$t_self = filter_var( $t_self, FILTER_SANITIZE_STRING );
+		$t_path = str_replace( basename( $t_self ), '', $t_self );
 		$t_path = basename( $t_path ) == "admin" ? dirname( $t_path ) . '/' : $t_path;
 		$t_path = basename( $t_path ) == "soap" ? dirname( dirname( $t_path ) ) . '/' : $t_path;
-		
+		if ( strpos( $t_path, '&#' ) ) {
+			echo 'Can not safely determine $g_path. Please set $g_path manually in config_inc.php';
+			die;
+		}
 
 		$t_url	= $t_protocol . '://' . $t_host . $t_path;
 
```
