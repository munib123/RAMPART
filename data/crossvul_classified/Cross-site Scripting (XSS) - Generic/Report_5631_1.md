# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5631_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5631_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 1-37 of the vulnerable file.

﻿/*
 * jPlayer Plugin for jQuery JavaScript Library
 * http://www.jplayer.org
 *
 * Copyright (c) 2009 - 2013 Happyworm Ltd
 * Dual licensed under the MIT and GPL licenses.
 *  - http://www.opensource.org/licenses/mit-license.php
 *  - http://www.gnu.org/copyleft/gpl.html
 *
 * Author: Mark J Panaghiston
 * Date: 20th April 2013
 */

package happyworm.jPlayer {
	public class JplayerStatus {

		public static const VERSION:String = "2.3.0"; // The version of the Flash jPlayer entity.

		public var volume:Number = 0.5; // Not affected by reset()
		public var muted:Boolean = false; // Not affected by reset()

		public var src:String;
		public var srcError:Boolean;

		public var srcSet:Boolean;
		public var isPlaying:Boolean;
		public var isSeeking:Boolean;

		public var playOnLoad:Boolean;
		public var playOnSeek:Boolean;

		public var isStartingDownload:Boolean;
		public var isLoading:Boolean;
		public var isLoaded:Boolean;

		public var pausePosition:Number;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
 package happyworm.jPlayer {
 	public class JplayerStatus {
 
-		public static const VERSION:String = "2.3.0"; // The version of the Flash jPlayer entity.
+		public static const VERSION:String = "2.3.1"; // The version of the Flash jPlayer entity.
 
 		public var volume:Number = 0.5; // Not affected by reset()
 		public var muted:Boolean = false; // Not affected by reset()
```
