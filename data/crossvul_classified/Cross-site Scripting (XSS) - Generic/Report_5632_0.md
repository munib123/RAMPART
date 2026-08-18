# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5632_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5632_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 1-31 of the vulnerable file.

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
 * Version: 2.3.1
 * Date: 14th May 2013
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
@@ -8,7 +8,7 @@
  *  - http://www.gnu.org/copyleft/gpl.html
  *
  * Author: Mark J Panaghiston
- * Version: 2.3.1
+ * Version: 2.3.2
  * Date: 14th May 2013
  *
  * FlashVars expected: (AS3 property of: loaderInfo.parameters)
@@ -223,10 +223,15 @@
 			}
 		}
 		private function checkFlashVars(p:Object):void {
-			// Check for direct access. Inspired by mediaelement.js - Also added name to object for non-IE browsers.
+			// Check for direct access. Inspired by mediaelement.js - Also added name to HTML object for non-IE browsers.
 			if(ExternalInterface.objectID != null && ExternalInterface.objectID.toString() != "") {
 				for each (var s:String in p) {
-					if(illegalChar(s) || illegalWord(s)) {
+					if(illegalChar(s)) {
+						securityIssue = true; // Found a security concern.
+					}
+				}
+				if(!securityIssue) {
+					if(jQueryIllegal(p.jQuery)) {
 						securityIssue = true; // Found a security concern.
 					}
 				}
@@ -239,17 +244,10 @@
 			var validParam:RegExp = /^[-A-Za-z0-9_.]+$/;
 			return !validParam.test(s);
 		}
-		private function illegalWord(s:String):Boolean {
-			// A blacklist of JavaScript commands that are a security concern.
-			var illegals:String = "eval document alert confirm prompt console";
-			if(Boolean(s)) { // Otherwise exception if parameter null.
-				for each (var illegal:String in illegals.split(' ')) {
-					if(s.indexOf(illegal) >= 0) {
-						return true; // Illegal word found
-					}
-				}
-			}
-			return false;
+		private function jQueryIllegal(s:String):Boolean {
+			// Check param contains the term jQuery.
+			var validParam:RegExp = /(jQuery)/;
+			return !validParam.test(s);
 		}
 		// switchType() here
 		private function listenToMp3(active:Boolean):void {
```
