# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5055_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5055_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 8-49 of the vulnerable file.


	import flash.media.Video;
	import flash.net.NetConnection;
	import flash.net.NetStream;

	import flash.geom.ColorTransform;

	import flash.filters.DropShadowFilter;
	import flash.utils.Timer;
	import flash.external.ExternalInterface;
	import flash.geom.Rectangle;

	import htmlelements.IMediaElement;
	import htmlelements.VideoElement;
	import htmlelements.AudioElement;
	import htmlelements.YouTubeElement;
	import htmlelements.DailyMotionElement;
	import htmlelements.HLSMediaElement;

	[SWF(backgroundColor="0x000000")] // Set SWF background color


	public class FlashMediaElement extends MovieClip {

		private var _mediaUrl:String;
		private var _jsInitFunction:String;
		private var _jsCallbackFunction:String;
		private var _autoplay:Boolean;
		private var _preload:String;
		private var _debug:Boolean = false;
		private var _isVideo:Boolean;
		private var _video:DisplayObject;
		private var _timerRate:Number;
		private var _enableSmoothing:Boolean;
		private var _allowedPluginDomain:String;
		private var _isFullScreen:Boolean = false;
		private var _startVolume:Number;
		private var _streamer:String = "";
		private var _enablePseudoStreaming:Boolean;
		private var _pseudoStreamingStartQueryParam:String;
		private var _fill:Boolean;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,8 +25,6 @@
 	import htmlelements.HLSMediaElement;
 
 	[SWF(backgroundColor="0x000000")] // Set SWF background color
-
-
 	public class FlashMediaElement extends MovieClip {
 
 		private var _mediaUrl:String;
@@ -99,8 +97,10 @@
 
 
 		public function FlashMediaElement() {
-			// check for security issues (borrowed from jPLayer)
-			checkFlashVars(loaderInfo.parameters);
+
+			if (isIllegalQuerystring()) {
+				return;
+			}
 
 			// allows this player to be called from a different domain than the HTML page hosting the player
 			CONFIG::cdnBuild {
@@ -108,25 +108,7 @@
 				Security.allowInsecureDomain('*');
 			}
 
-			if (securityIssue) {
-				return;
-			}
-
-			// get parameters
-			// Use only FlashVars, ignore QueryString
-			var params:Object, pos:int, query:Object;
-
-			params = LoaderInfo(this.root.loaderInfo).parameters;
-			pos = root.loaderInfo.url.indexOf('?');
-			if (pos !== -1) {
-				query = parseStr(root.loaderInfo.url.substr(pos + 1));
-
-				for (var key:String in params) {
-					if (query.hasOwnProperty(trim(key))) {
-						delete params[key];
-					}
-				}
-			}
+			var params:Object = LoaderInfo(this.root.loaderInfo).parameters;
 
 			CONFIG::debugBuild {
 				_debug = (params['debug'] != undefined) ? (String(params['debug']) == "true") : false;
@@ -456,42 +438,19 @@
 			}
 		}
 
-		// borrowed from jPLayer
-		// https://github.com/happyworm/jPlayer/blob/e8ca190f7f972a6a421cb95f09e138720e40ed6d/actionscript/Jplayer.as#L228
-		private function checkFlashVars(p:Object):void {
-			var i:Number = 0;
-			for (var s:String in p) {
-				if (isIllegalChar(p[s], s === 'file')) {
-					securityIssue = true; // Illegal char found
-				}
-				i++;
-			}
-			if (i === 0 || securityIssue) {
-				directAccess = true;
-			}
-		}
-
-		private static function parseStr (str:String) : Object {
-			var hash:Object = {},
-				arr1:Array, arr2:Array;
-
-			str = unescape(str).replace(/\+/g, " ");
-
-			arr1 = str.split('&');
-			if (!arr1.length) {
-				return {};
-			}
-
-			for (var i:uint = 0, length:uint = arr1.length; i < length; i++) {
-				arr2 = arr1[i].split('=');
-				if (!arr2.length) {
-					continue;
-				}
-				hash[trim(arr2[0])] = trim(arr2[1]);
-			}
-			return hash;
-		}
-
+		private function isIllegalQuerystring():Boolean {
+			var query:String = '';
+			var pos:Number = root.loaderInfo.url.indexOf('?') ;
+			
+			if ( pos > -1 ) {
+			    query = root.loaderInfo.url.substring( pos );
+			    if ( ! /^\?\d+$/.test( query ) ) {
+			        return true;
+			    }
+			}			
+			
+			return false;
+		}
 
 		private static function trim(str:String) : String {
 			if (!str) {
@@ -499,21 +458,6 @@
 			}
 
 			return str.toString().replace(/^\s*/, '').replace(/\s*$/, '');
-		}
-
-		private function isIllegalChar(s:String, isUrl:Boolean):Boolean {
-			var illegals:String = "' \" ( ) { } * + \\ < >";
-			if (isUrl) {
-				illegals = "\" { } \\ < >";
-			}
-			if (Boolean(s)) { // Otherwise exception if parameter null.
-				for each (var illegal:String in illegals.split(' ')) {
-					if (s.indexOf(illegal) >= 0) {
-						return true; // Illegal char found
-					}
-				}
-			}
-			return false;
 		}
 
 		// START: Controls and events
```
