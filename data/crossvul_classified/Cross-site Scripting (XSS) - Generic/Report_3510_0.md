# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3510_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3510_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php
/**
 * Loads common functions used throughout the site.
 *
 * @copyright (C) 2008-2009 PunBB, partially based on code (C) 2008-2009 FluxBB.org
 * @license http://www.gnu.org/licenses/gpl.html GPL version 2 or higher
 * @package PunBB
 */

//
// Common helpers and forum's wrappers for PHP functions
//

// Encodes the contents of $str so that they are safe to output on an (X)HTML page
function forum_htmlencode($str)
{
	$return = ($hook = get_hook('fn_forum_htmlencode_start')) ? eval($hook) : null;
	if ($return != null)
		return $return;

	return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}


// Trim whitespace including non-breaking space
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 /**
  * Loads common functions used throughout the site.
  *
- * @copyright (C) 2008-2009 PunBB, partially based on code (C) 2008-2009 FluxBB.org
+ * @copyright (C) 2008-2011 PunBB, partially based on code (C) 2008-2009 FluxBB.org
  * @license http://www.gnu.org/licenses/gpl.html GPL version 2 or higher
  * @package PunBB
  */
@@ -2672,7 +2672,7 @@
 		<div class="ct-box info-box">
 			<p><?php echo $lang_common['CSRF token mismatch'] ?></p>
 		</div>
-		<form class="frm-form" method="post" accept-charset="utf-8" action="<?php echo $forum_page['form_action'] ?>">
+		<form class="frm-form" method="post" accept-charset="utf-8" action="<?php echo forum_htmlencode($forum_page['form_action']) ?>">
 			<div class="hidden">
 				<?php echo implode("\n\t\t\t\t", $forum_page['hidden_fields'])."\n" ?>
 			</div>
```
