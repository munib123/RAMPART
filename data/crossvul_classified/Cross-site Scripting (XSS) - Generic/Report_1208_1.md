# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1208_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1208_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 23-63 of the vulnerable file.

 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require("guiconfig.inc");
require("freeradius.inc");

function get_file($file) {
	$files['radiusd'] = FREERADIUS_RADDB . "/radiusd.conf";
	$files['eap'] = FREERADIUS_MODSENABLED . "/eap";
	$files['sql'] = FREERADIUS_MODSENABLED . "/sql";
	$files['clients'] = FREERADIUS_RADDB . "/clients.conf";
	$files['users'] = FREERADIUS_RADDB . "/users";
	$files['macs'] = FREERADIUS_RADDB . "/authorized_macs";
	$files['virtual-server-default'] = FREERADIUS_RADDB . "/sites-enabled/default";
	$files['ldap'] = FREERADIUS_MODSENABLED . "/ldap";

	if ($files[$file] != "" && file_exists($files[$file])) {
		print '<pre>';
		print $files[$file] . "\n" . file_get_contents($files[$file]);
		print '</pre>';
	}
}

if ($_REQUEST['file'] != "") {
	get_file($_REQUEST['file']);
	return;
}

$pgtitle = array(gettext("Package"), gettext("FreeRADIUS"), gettext("View Configuration"));
require("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Users"), false, "/pkg.php?xml=freeradius.xml");
$tab_array[] = array(gettext("MACs"), false, "/pkg.php?xml=freeradiusauthorizedmacs.xml");
$tab_array[] = array(gettext("NAS / Clients"), false, "/pkg.php?xml=freeradiusclients.xml");
$tab_array[] = array(gettext("Interfaces"), false, "/pkg.php?xml=freeradiusinterfaces.xml");
$tab_array[] = array(gettext("Settings"), false, "/pkg_edit.php?xml=freeradiussettings.xml&id=0");
$tab_array[] = array(gettext("EAP"), false, "/pkg_edit.php?xml=freeradiuseapconf.xml&id=0");
$tab_array[] = array(gettext("SQL"), false, "/pkg_edit.php?xml=freeradiussqlconf.xml&id=0");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,7 +40,7 @@
 
 	if ($files[$file] != "" && file_exists($files[$file])) {
 		print '<pre>';
-		print $files[$file] . "\n" . file_get_contents($files[$file]);
+		print $files[$file] . "\n" . htmlspecialchars(file_get_contents($files[$file]));
 		print '</pre>';
 	}
 }
```
