# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4473_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4473_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<?php
/**
 * Plugin Name: Envira Gallery Lite
 * Plugin URI:  http://enviragallery.com
 * Description: Envira Gallery is the best responsive WordPress gallery plugin. This is the Lite version.
 * Author:      Envira Gallery Team
 * Author URI:  http://enviragallery.com
 * Version:     1.8.3.2
 * Text Domain: envira-gallery-lite
 *
 * Envira Gallery is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * any later version.
 *
 * Envira Gallery is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Envira Gallery. If not, see <http://www.gnu.org/licenses/>.
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,7 @@
  * Description: Envira Gallery is the best responsive WordPress gallery plugin. This is the Lite version.
  * Author:      Envira Gallery Team
  * Author URI:  http://enviragallery.com
- * Version:     1.8.3.2
+ * Version:     1.8.3.3
  * Text Domain: envira-gallery-lite
  *
  * Envira Gallery is free software: you can redistribute it and/or modify
@@ -53,7 +53,7 @@
 	 *
 	 * @var string
 	 */
-	public $version = '1.8.3.2';
+	public $version = '1.8.3.3';
 
 	/**
 	 * The name of the plugin.
```
