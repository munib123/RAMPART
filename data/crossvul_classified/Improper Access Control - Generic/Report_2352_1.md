# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 2352_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2352_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 9-49 of the vulnerable file.

# MantisBT is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.

	/**
	 * @package MantisBT
	 * @copyright Copyright (C) 2000 - 2002  Kenzaburo Ito - kenito@300baud.org
	 * @copyright Copyright (C) 2002 - 2014  MantisBT Team - mantisbt-dev@lists.sourceforge.net
	 * @author Marcello Scata' <marcelloscata at users.sourceforge.net> ITALY
	 * @link http://www.mantisbt.org
	 */
	 /**
	  * MantisBT Core API's
	  */
	require_once( 'core.php' );

	$f_public_key = gpc_get_int( 'public_key' );

	$t_key = utf8_strtolower( utf8_substr( md5( config_get( 'password_confirm_hash_magic_string' ) . $f_public_key ), 1, 5) );
	$t_system_font_folder = get_font_path();
	$t_font_per_captcha = config_get( 'font_per_captcha' );

	$t_captcha_init = array(
		'TTF_folder'     => $t_system_font_folder,
		'TTF_RANGE'      => array( $t_font_per_captcha )
	);

	$captcha = new masc_captcha( $t_captcha_init );
	$captcha->make_captcha( $t_key );

#
# The class below was derived from
# http://www.phpclasses.org/browse/package/1163.html
#
# *** 3.0 Author
# Pascal Rehfeldt
# Pascal@Pascal-Rehfeldt.com
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,9 +26,9 @@
 	  */
 	require_once( 'core.php' );
 
-	$f_public_key = gpc_get_int( 'public_key' );
-
-	$t_key = utf8_strtolower( utf8_substr( md5( config_get( 'password_confirm_hash_magic_string' ) . $f_public_key ), 1, 5) );
+	$t_form_key = session_get( CAPTCHA_KEY );
+
+	$t_key = utf8_strtolower( utf8_substr( md5( config_get( 'password_confirm_hash_magic_string' ) . $t_form_key ), 1, 5) );
 	$t_system_font_folder = get_font_path();
 	$t_font_per_captcha = config_get( 'font_per_captcha' );
 
```
