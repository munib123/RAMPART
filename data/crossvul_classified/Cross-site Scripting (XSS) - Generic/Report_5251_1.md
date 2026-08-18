# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5251_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5251_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 16-56 of the vulnerable file.

 * along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @copyright Copyright 2002  MantisBT Team - mantisbt-dev@lists.sourceforge.net
 * @link http://www.mantisbt.org
 * @package MantisBT
 */

/**
 * Event Declarations
 * Please view the Plugin Events Reference for details on each event.
 * http://www.mantisbt.org/wiki/doku.php/mantisbt:plugins_events
 */

# Declare supported plugin events
event_declare_many( array(
	# Events specific to plugins
	'EVENT_PLUGIN_INIT' => EVENT_TYPE_EXECUTE,

	# Events specific to the core system
	'EVENT_CORE_READY' => EVENT_TYPE_EXECUTE,

	# MantisBT Layout Events
	'EVENT_LAYOUT_RESOURCES' => EVENT_TYPE_OUTPUT,
	'EVENT_LAYOUT_BODY_BEGIN' => EVENT_TYPE_OUTPUT,
	'EVENT_LAYOUT_PAGE_HEADER' => EVENT_TYPE_OUTPUT,
	'EVENT_LAYOUT_CONTENT_BEGIN' => EVENT_TYPE_OUTPUT,
	'EVENT_LAYOUT_CONTENT_END' => EVENT_TYPE_OUTPUT,
	'EVENT_LAYOUT_PAGE_FOOTER' => EVENT_TYPE_OUTPUT,
	'EVENT_LAYOUT_BODY_END' => EVENT_TYPE_OUTPUT,

	# Events for displaying data
	'EVENT_DISPLAY_BUG_ID' => EVENT_TYPE_CHAIN,
	'EVENT_DISPLAY_TEXT' => EVENT_TYPE_CHAIN,
	'EVENT_DISPLAY_FORMATTED' => EVENT_TYPE_CHAIN,
	'EVENT_DISPLAY_RSS' => EVENT_TYPE_CHAIN,
	'EVENT_DISPLAY_EMAIL' => EVENT_TYPE_CHAIN,
	'EVENT_DISPLAY_EMAIL_BUILD_SUBJECT' => EVENT_TYPE_CHAIN,

	# Menu Events
	'EVENT_MENU_MAIN' => EVENT_TYPE_DEFAULT,
	'EVENT_MENU_MAIN_FRONT' => EVENT_TYPE_DEFAULT,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,6 +33,7 @@
 
 	# Events specific to the core system
 	'EVENT_CORE_READY' => EVENT_TYPE_EXECUTE,
+	'EVENT_CORE_HEADERS' => EVENT_TYPE_EXECUTE,
 
 	# MantisBT Layout Events
 	'EVENT_LAYOUT_RESOURCES' => EVENT_TYPE_OUTPUT,
```
