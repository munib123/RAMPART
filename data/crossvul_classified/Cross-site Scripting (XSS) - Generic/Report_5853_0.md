# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5853_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5853_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 65-105 of the vulnerable file.


      // clip hack properties
      private var seekTo:Number;
      private var clipUrl:String;

      // video stream
      private var conn:NetConnection;
      private var stream:NetStream;
      private var video:Video;
      private var logo:Logo;

      private var timer:Timer;


      /* constructor */
      public function Flowplayer() {
         Security.allowDomain("*");
         stage.scaleMode = StageScaleMode.NO_SCALE;
         stage.align = StageAlign.TOP_LEFT;

         conf = this.loaderInfo.parameters;

         // The API
         for (var i:Number = 0; i < INTERFACE.length; i++) {
            ExternalInterface.addCallback("__" + INTERFACE[i], this[INTERFACE[i]]);
         }

         // IE needs mouse / keyboard events
         stage.addEventListener(MouseEvent.CLICK, function(e:MouseEvent):void {
            fire("click", null);
         });

         stage.addEventListener(KeyboardEvent.KEY_DOWN, function(e:KeyboardEvent):void {
            fire("keydown", e.keyCode);
         });

         stage.addEventListener(Event.RESIZE, arrange);

         // timeupdate event
         timer = new Timer(250);
         timer.addEventListener("timer", timeupdate);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,6 +82,7 @@
          stage.scaleMode = StageScaleMode.NO_SCALE;
          stage.align = StageAlign.TOP_LEFT;
 
+         if (this.loaderInfo.url.indexOf("callback=") > 0) throw new Error("Security error");
          conf = this.loaderInfo.parameters;
 
          // The API
@@ -231,7 +232,7 @@
 
          conf.url = unescape(conf.url);
 
-         if (conf.debug) fire("debug.url", conf.url);
+         debug("debug.url", conf.url);
 
          conn = new NetConnection();
 
@@ -430,6 +431,7 @@
     private function debug(msg:String, data:Object = null):void {
         if (!conf.debug) return;
         fire("debug: " + msg, data);
+//        ExternalInterface.call("console.log", msg, data);
     }
 
     private function fire(type:String, data:Object = null):void {
```
