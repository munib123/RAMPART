# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 1048_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1048_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 335-375 of the vulnerable file.

		if( !isset( $this->formats[$p_format] ) ) {
			trigger_error( ERROR_GENERIC, ERROR );
		}

		$t_binary = $this->formats[$p_format]['binary'];
		$t_type = $this->formats[$p_format]['type'];
		$t_mime = $this->formats[$p_format]['mime'];

		# Send Content-Type header, if requested.
		if( $p_headers ) {
			header( 'Content-Type: ' . $t_mime );
		}
		# Retrieve the source dot document into a buffer
		ob_start();
		$this->generate();
		$t_dot_source = ob_get_contents();
		ob_end_clean();

		# Start dot process

		$t_command = $this->graphviz_tool . ' -T' . $p_format;
		$t_descriptors = array(
			0 => array( 'pipe', 'r', ),
			1 => array( 'pipe', 'w', ),
			2 => array( 'file', 'php://stderr', 'w', ),
			);

		$t_pipes = array();
		$t_proccess = proc_open( $t_command, $t_descriptors, $t_pipes );

		if( is_resource( $t_proccess ) ) {
			# Filter generated output through dot
			fwrite( $t_pipes[0], $t_dot_source );
			fclose( $t_pipes[0] );

			if( $p_headers ) {
				# Headers were requested, use another output buffer to
				# retrieve the size for Content-Length.
				ob_start();
				while( !feof( $t_pipes[1] ) ) {
					echo fgets( $t_pipes[1], 1024 );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -352,7 +352,7 @@
 
 		# Start dot process
 
-		$t_command = $this->graphviz_tool . ' -T' . $p_format;
+		$t_command = escapeshellcmd( $this->graphviz_tool . ' -T' . $p_format );
 		$t_descriptors = array(
 			0 => array( 'pipe', 'r', ),
 			1 => array( 'pipe', 'w', ),
```
