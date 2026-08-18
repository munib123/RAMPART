# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5630_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5630_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 222-262 of the vulnerable file.

				ExternalInterface.addCallback("fl_play_head", fl_play_head);
				ExternalInterface.addCallback("fl_volume", fl_volume);
				ExternalInterface.addCallback("fl_mute", fl_mute);

				ExternalInterface.call(jQuery, "jPlayerFlashEvent", JplayerEvent.JPLAYER_READY, extractStatusData(commonStatus)); // See JplayerStatus() class for version number.
			}
		}
		private function checkFlashVars(p:Object):void {
			var i:Number = 0;
			for each (var s:String in p) {
				if(illegalChar(s)) {
					securityIssue = true; // Illegal char found
				}
				i++;
			}
			if(i === 0 || securityIssue) {
				directAccess = true;
			}
		}
		private function illegalChar(s:String):Boolean {
			var illegals:String = "' \" ( ) { } * + / \\ < > = document";
			if(Boolean(s)) { // Otherwise exception if parameter null.
				for each (var illegal:String in illegals.split(' ')) {
					if(s.indexOf(illegal) >= 0) {
						return true; // Illegal char found
					}
				}
			}
			return false;
		}
		// switchType() here
		private function listenToMp3(active:Boolean):void {
			if(active) {
				myMp3Player.addEventListener(JplayerEvent.JPLAYER_ERROR, jPlayerFlashEvent);
				myMp3Player.addEventListener(JplayerEvent.JPLAYER_PROGRESS, jPlayerFlashEvent);
				myMp3Player.addEventListener(JplayerEvent.JPLAYER_TIMEUPDATE, jPlayerFlashEvent);
				myMp3Player.addEventListener(JplayerEvent.JPLAYER_ENDED, jPlayerFlashEvent);
				
				myMp3Player.addEventListener(JplayerEvent.JPLAYER_PLAY, jPlayerFlashEvent);
				myMp3Player.addEventListener(JplayerEvent.JPLAYER_PAUSE, jPlayerFlashEvent);
				myMp3Player.addEventListener(JplayerEvent.JPLAYER_LOADSTART, jPlayerFlashEvent);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -239,7 +239,7 @@
 			}
 		}
 		private function illegalChar(s:String):Boolean {
-			var illegals:String = "' \" ( ) { } * + / \\ < > = document";
+			var illegals:String = "' \" ( ) { } * + / \\ < > = document alert";
 			if(Boolean(s)) { // Otherwise exception if parameter null.
 				for each (var illegal:String in illegals.split(' ')) {
 					if(s.indexOf(illegal) >= 0) {
```
