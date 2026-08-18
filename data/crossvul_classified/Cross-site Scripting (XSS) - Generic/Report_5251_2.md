# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5251_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5251_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 11-51 of the vulnerable file.

# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.

/**
 * HTTP API
 *
 * Provides functions to manage HTTP response headers.
 *
 * @package CoreAPI
 * @subpackage HTTPAPI
 * @copyright Copyright 2002  MantisBT Team - mantisbt-dev@lists.sourceforge.net
 * @link http://www.mantisbt.org
 *
 * @uses config_api.php
 */

require_api( 'config_api.php' );

/**
 * Checks to see if script was queried through the HTTPS protocol
 * @return boolean True if protocol is HTTPS
 */
function http_is_protocol_https() {
	return !empty( $_SERVER['HTTPS'] ) && ( utf8_strtolower( $_SERVER['HTTPS'] ) != 'off' );
}

/**
 * Check to see if the client is using Microsoft Internet Explorer so we can
 * enable quirks and hacky non-standards-compliant workarounds.
 * @return boolean True if Internet Explorer is detected as the user agent
 */
function is_browser_internet_explorer() {
	$t_user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : 'none';

	if( strpos( $t_user_agent, 'MSIE' ) ) {
		return true;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,12 @@
 require_api( 'config_api.php' );
 
 /**
+ * The Content-Security-Policy settings array.  Use http_csp_add() to update it.
+ * @var array
+ */
+$g_csp = array();
+
+/**
  * Checks to see if script was queried through the HTTPS protocol
  * @return boolean True if protocol is HTTPS
  */
@@ -139,6 +145,64 @@
 }
 
 /**
+ * Add a Content-Security-Policy directive.
+ *
+ * @param  string $p_type  The directive type, e.g. style-src, script-src.
+ * @param  string $p_value The directive value, e.g. 'self', https://ajax.googleapis.com
+ * @return void
+ */
+function http_csp_add( $p_type, $p_value ) {
+	global $g_csp;
+
+	if ( $g_csp === null ) {
+		# Development error, headers already emitted.
+		trigger_error( ERROR_GENERIC, ERROR );
+	}
+
+	if ( isset( $g_csp[$p_type] ) ) {
+		if ( !in_array( $p_value, $g_csp[$p_type] ) ) {
+			$g_csp[$p_type][] = $p_value;
+		}
+	} else {
+		$g_csp[$p_type] = array( $p_value );
+	}
+}
+
+/**
+ * Constructs the value of the CSP header.
+ * @return string CSP header value.
+ */
+function http_csp_value() {
+	global $g_csp;
+
+	if ( $g_csp === null ) {
+		# Development error, headers already emitted.
+		trigger_error( ERROR_GENERIC, ERROR );
+	}
+
+	$t_csp_value = '';
+
+	foreach ( $g_csp as $t_key => $t_values ) {
+		$t_csp_value .= $t_key . ' ' . implode( ' ', $t_values ) . '; ';
+	}
+
+	$t_csp_value = trim( $t_csp_value, '; ' );
+
+	return $t_csp_value;
+}
+
+/**
+ * Send header for Content-Security-Policy.
+ * @return void
+ */
+function http_csp_emit_header() {
+	header( 'Content-Security-Policy: ' . http_csp_value() );
+
+	global $g_csp;
+	$g_csp = null;
+}
+
+/**
  * Set security headers (frame busting, clickjacking/XSS/CSRF protection).
  * @return void
  */
@@ -147,32 +211,26 @@
 		header( 'X-Frame-Options: DENY' );
 
 		# Define Content Security Policy
-		$t_csp = array(
-			"default-src 'self'",
-			"frame-ancestors 'none'",
-		);
-
-		$t_style_src = "style-src 'self'";
-		$t_script_src = "script-src 'self'";
+		http_csp_add( 'default-src', "'self'" );
+		http_csp_add( 'frame-ancestors', "'none'" );
+		http_csp_add( 'style-src', "'self'" );
+		http_csp_add( 'script-src', "'self'" );
+		http_csp_add( 'img-src', "'self'" );
 
 		# White list the CDN urls (if enabled)
 		if ( config_get_global( 'cdn_enabled' ) == ON ) {
 			$t_cdn_url = 'https://ajax.googleapis.com';
-			$t_style_src .= " $t_cdn_url";
-			$t_script_src .= " $t_cdn_url";
+			http_csp_add( 'style-src', $t_cdn_url );
+			http_csp_add( 'script-src', $t_cdn_url );
 		}
 
 		# Relaxing policy for roadmap page to allow inline styles
 		# This is a workaround to fix the broken progress bars (see #19501)
 		if( 'roadmap_page.php' == basename( $_SERVER['SCRIPT_NAME'] ) ) {
-			$t_style_src .= " 'unsafe-inline'";
-		}
-
-		$t_csp[] = $t_style_src;
-		$t_csp[] = $t_script_src;
-
-		# Set CSP header
-		header( 'Content-Security-Policy: ' . implode('; ', $t_csp) );
+			http_csp_add( 'style-src', "'unsafe-inline'" );
+		}
+
+		http_csp_emit_header();
 
 		if( http_is_protocol_https() ) {
 			header( 'Strict-Transport-Security: max-age=7776000' );
```
