# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2363_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2363_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 442-482 of the vulnerable file.

					# We might as well create the link here even if the bug
					#  doesnt exist.  In the case above we dont want to do
					#  the summary lookup on a non-existant bug.  But here, we
					#  can create the link and by the time it is clicked on, the
					#  bug may exist.
					$t_bug_id = bugnote_get_field( (int)$p_array[2], \'bug_id\' );
					if ( bug_exists( $t_bug_id ) ) {
						return $p_array[1] . string_get_bugnote_view_url_with_fqdn( $t_bug_id, (int)$p_array[2], null );
					} else {
						return $p_array[0];
					}
					'
				);
		}
	}
	$p_string = preg_replace_callback( '/(^|[^\w])' . preg_quote( $t_tag, '/' ) . '(\d+)\b/', $string_process_bugnote_link_callback[$p_include_anchor][$p_detail_info][$p_fqdn], $p_string );
	return $p_string;
}

/**
 * Detect URLs and email addresses in the string and replace them with href anchors
 * @param string $p_string
 * @return string
 */
function string_insert_hrefs( $p_string ) {
	static $s_url_regex = null;
	static $s_email_regex = null;
	static $s_anchor_regex = '/(<a[^>]*>.*?<\/a>)/is';

	if( !config_get( 'html_make_links' ) ) {
		return $p_string;
	}

	$t_change_quotes = false;
	if( ini_get_bool( 'magic_quotes_sybase' ) && function_exists( 'ini_set' ) ) {
		$t_change_quotes = true;
		ini_set( 'magic_quotes_sybase', false );
	}

	# Initialize static variables
	if ( is_null( $s_url_regex ) ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -459,7 +459,8 @@
 }
 
 /**
- * Detect URLs and email addresses in the string and replace them with href anchors
+ * Search email addresses and URLs for a few common protocols in the given
+ * string, and replace occurences with href anchors.
  * @param string $p_string
  * @return string
  */
@@ -480,8 +481,10 @@
 
 	# Initialize static variables
 	if ( is_null( $s_url_regex ) ) {
-		# URL regex
-		$t_url_protocol = '(?:[[:alpha:]][-+.[:alnum:]]*):\/\/';
+		# URL protocol. The regex accepts a small subset from the list of valid
+		# IANA permanent and provisional schemes defined in
+		# http://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
+		$t_url_protocol = '(?:https?|s?ftp|file|irc[6s]?|ssh|telnet|nntp|git|svn(?:\+ssh)?|cvs):\/\/';
 
 		# %2A notation in url's
 		$t_url_hex = '%[[:digit:]A-Fa-f]{2}';
```
