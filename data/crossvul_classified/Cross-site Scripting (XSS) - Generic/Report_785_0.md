# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 785_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `785_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2077-2117 of the vulnerable file.

 *
 * @param $url string e.g : wp-statistics.com
 * @return bool|string
 */
function wp_statistics_get_site_title( $url ) {

	//Get ody Page
	$html = wp_statistics_get_html_page( $url );
	if ( $html === false ) {
		return false;
	}

	//Get Page Title
	if ( class_exists( 'DOMDocument' ) ) {
		$dom = new DOMDocument;
		@$dom->loadHTML( $html );
		$title = '';
		if ( isset( $dom ) and $dom->getElementsByTagName( 'title' )->length > 0 ) {
			$title = $dom->getElementsByTagName( 'title' )->item( '0' )->nodeValue;
		}
		return ( wp_strip_all_tags( $title ) == "" ? false : $title );
	}

	return false;
}


/**
 * Get WebSite IP Server And Country Name
 *
 * @param $url string domain name e.g : wp-statistics.com
 * @return array
 */
function wp_statistics_get_domain_server( $url ) {
	global $WP_Statistics;

	//Create Empty Object
	$result = array(
		'ip'      => '',
		'country' => ''
	);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2094,7 +2094,7 @@
 		if ( isset( $dom ) and $dom->getElementsByTagName( 'title' )->length > 0 ) {
 			$title = $dom->getElementsByTagName( 'title' )->item( '0' )->nodeValue;
 		}
-		return ( wp_strip_all_tags( $title ) == "" ? false : $title );
+		return ( wp_strip_all_tags( $title ) == "" ? false : wp_strip_all_tags( $title ) );
 	}
 
 	return false;
```
