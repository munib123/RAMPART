# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5631_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5631_0`)

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
 * Version: 2.3.0
 * Date: 20th April 2013
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
- * Version: 2.3.0
- * Date: 20th April 2013
+ * Version: 2.3.1
+ * Date: 14th May 2013
  *
  * FlashVars expected: (AS3 property of: loaderInfo.parameters)
  *	id: 	(URL Encoded: String) Id of jPlayer instance
@@ -69,15 +69,14 @@
 		private var isMp3:Boolean = false;
 		private var isVideo:Boolean = false;
 
-		private var securityIssue:Boolean = false; // When SWF parameters contain illegal characters
-		private var directAccess:Boolean = false; // When SWF visited directly with no parameters (or when security issue detected)
+		private var securityIssue:Boolean = false; // On direct access and when SWF parameters contain illegal characters
 
 		private var txLog:TextField;
 		private var debug:Boolean = false; // Set debug to false for release compile!
 		private var localAIRDebug:Boolean = false; // This is autodetermined by AIR app - leave false!
 
 		private var traceOut:TraceOut;
-		//private var outgoing_lc = new LocalConnection ();
+
 		public function Jplayer() {
 
 			flash.system.Security.allowDomain("*");
@@ -90,6 +89,7 @@
 			stage.align = StageAlign.TOP_LEFT;
 
 			if(!securityIssue) {
+				// The jQuery param is the primary cause of security concerns.
 				jQuery = loaderInfo.parameters.jQuery + "('#" + loaderInfo.parameters.id + "').jPlayer";
 				commonStatus.volume = Number(loaderInfo.parameters.vol);
 				commonStatus.muted = loaderInfo.parameters.muted == "true";
@@ -128,7 +128,7 @@
 			contextMenu = myContextMenu;
 
 			// Log console for dev compile option: debug
-			if(debug || directAccess) {
+			if(debug || securityIssue) {
 				txLog = new TextField();
 				txLog.x = 5;
 				txLog.y = 5;
@@ -137,17 +137,13 @@
 				txLog.backgroundColor = 0xEEEEFF;
 				txLog.border = true;
 				txLog.background = true;
+				txLog.multiline = true;
 				txLog.text = "jPlayer " + JplayerStatus.VERSION;
 
-				if(debug) {
-					txLog.multiline = true;
+				if(securityIssue) {
+					txLog.visible = true;
+				} else if(debug) {
 					txLog.visible = false;
-				} else if(directAccess) {
-					txLog.visible = true;
-				}
-				if(debug && directAccess) {
-					txLog.visible = true;
-					log("Direct Access");
 				}
 
 				this.addChild(txLog);
@@ -227,23 +223,29 @@
 			}
 		}
 		private function checkFlashVars(p:Object):void {
-			var i:Number = 0;
-			for each (var s:String in p) {
-				if(illegalChar(s)) {
-					securityIssue = true; // Illegal char found
+			// Check for direct access. Inspired by mediaelement.js - Also added name to object for non-IE browsers.
+			if(ExternalInterface.objectID != null && ExternalInterface.objectID.toString() != "") {
+				for each (var s:String in p) {
+					if(illegalChar(s) || illegalWord(s)) {
+						securityIssue = true; // Found a security concern.
+					}
 				}
-				i++;
-			}
-			if(i === 0 || securityIssue) {
-				directAccess = true;
+			} else {
+				securityIssue = true; // Direct access disables the callbacks, which were a security concern.
 			}
 		}
 		private function illegalChar(s:String):Boolean {
-			var illegals:String = "' \" ( ) { } * + / \\ < > = document alert";
+			// A whitelist of accepted chars.
+			var validParam:RegExp = /^[-A-Za-z0-9_.]+$/;
+			return !validParam.test(s);
+		}
+		private function illegalWord(s:String):Boolean {
+			// A blacklist of JavaScript commands that are a security concern.
+			var illegals:String = "eval document alert confirm prompt console";
 			if(Boolean(s)) { // Otherwise exception if parameter null.
 				for each (var illegal:String in illegals.split(' ')) {
 					if(s.indexOf(illegal) >= 0) {
-						return true; // Illegal char found
+						return true; // Illegal word found
 					}
 				}
 			}
@@ -552,7 +554,7 @@
 					resizeEntity(videoItem, mediaX, mediaY, mediaWidth, mediaHeight);
 				}
 			}
-			if((debug || directAccess) && stage.stageWidth > 20 && stage.stageHeight > 20) {
+			if((debug || securityIssue) && stage.stageWidth > 20 && stage.stageHeight > 20) {
 				txLog.width = stage.stageWidth - 10;
 				txLog.height = stage.stageHeight - 10;
 			}
```
