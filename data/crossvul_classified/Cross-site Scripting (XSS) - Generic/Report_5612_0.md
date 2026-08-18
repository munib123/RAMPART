# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5612_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5612_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 1-32 of the vulnerable file.

/*
 * jPlayer Plugin for jQuery JavaScript Library
 * http://www.jplayer.org
 *
 * Copyright (c) 2009 - 2013 Happyworm Ltd
 * Dual licensed under the MIT and GPL licenses.
 *  - http://www.opensource.org/licenses/mit-license.php
 *  - http://www.gnu.org/copyleft/gpl.html
 *
 * Author: Mark J Panaghiston
 * Version: 2.2.19
 * Date: 29th January 2013
 *
 * FlashVars expected: (AS3 property of: loaderInfo.parameters)
 *	id: 	(URL Encoded: String) Id of jPlayer instance
 *	vol:	(Number) Sets the initial volume
 *	muted:	(Boolean in a String) Sets the initial muted state
 *	jQuery:	(URL Encoded: String) Sets the jQuery var name. Used with: someVar = jQuery.noConflict(true);
 *
 * Compiled using: Adobe Flex Compiler (mxmlc) Version 4.5.1 build 21328
 */

package {
	import flash.system.Security;
	import flash.external.ExternalInterface;

	import flash.utils.Timer;
	import flash.events.TimerEvent;
	
	import flash.text.TextField;
	import flash.text.TextFormat;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,8 +8,8 @@
  *  - http://www.gnu.org/copyleft/gpl.html
  *
  * Author: Mark J Panaghiston
- * Version: 2.2.19
- * Date: 29th January 2013
+ * Version: 2.2.20
+ * Date: 21st March 2013
  *
  * FlashVars expected: (AS3 property of: loaderInfo.parameters)
  *	id: 	(URL Encoded: String) Id of jPlayer instance
@@ -70,7 +70,7 @@
 		private var isVideo:Boolean = false;
 
 		private var securityIssue:Boolean = false; // When SWF parameters contain illegal characters
-		private var directAccess:Boolean = false; // When SWF visited directly with no parameters
+		private var directAccess:Boolean = false; // When SWF visited directly with no parameters (or when security issue detected)
 
 		private var txLog:TextField;
 		private var debug:Boolean = false; // Set debug to false for release compile!
@@ -233,12 +233,12 @@
 				}
 				i++;
 			}
-			if(i === 0) {
+			if(i === 0 || securityIssue) {
 				directAccess = true;
 			}
 		}
 		private function illegalChar(s:String):Boolean {
-			var illegals:String = "' \" ( ) { } * + /";
+			var illegals:String = "' \" ( ) { } * + / \\ < > = document";
 			if(Boolean(s)) { // Otherwise exception if parameter null.
 				for each (var illegal:String in illegals.split(' ')) {
 					if(s.indexOf(illegal) >= 0) {
```
