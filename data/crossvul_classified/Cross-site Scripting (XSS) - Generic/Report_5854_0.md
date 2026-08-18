# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5854_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5854_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 66-106 of the vulnerable file.


   // clip hack properties
   private var seekTo:Number;
   private var clipUrl:String;

   // video stream
   private var connection:Connection;
   private var stream:NetStream;
   private var video:Video;
   private var logo:DisplayObject;

   private var timer:Timer;


   /* constructor */
   public function Flowplayer() {
      Security.allowDomain("*");
      stage.scaleMode = StageScaleMode.NO_SCALE;
      stage.align = StageAlign.TOP_LEFT;

      if (this.loaderInfo.url.indexOf("callback=") > 0) throw new Error("Security error");
      conf = this.loaderInfo.parameters;

      // IE needs mouse / keyboard events
      stage.addEventListener(MouseEvent.CLICK, function (e:MouseEvent):void {
         fire("click", null);
      });

      stage.addEventListener(KeyboardEvent.KEY_DOWN, function (e:KeyboardEvent):void {
         fire("keydown", e.keyCode);
      });

      stage.addEventListener(Event.RESIZE, arrange);

      var player:Flowplayer = this;
      this.addEventListener(Event.ADDED_TO_STAGE, function (e:Event):void {
         // The API
         for (var i:Number = 0; i < INTERFACE.length; i++) {
            debug("creating callback " + INTERFACE[i] + " id == " + ExternalInterface.objectID);
            ExternalInterface.addCallback("__" + INTERFACE[i], player[INTERFACE[i]]);
         }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,7 +83,8 @@
       stage.scaleMode = StageScaleMode.NO_SCALE;
       stage.align = StageAlign.TOP_LEFT;
 
-      if (this.loaderInfo.url.indexOf("callback=") > 0) throw new Error("Security error");
+      var swfUrl:String = decodeURIComponent(this.loaderInfo.url);
+      if (swfUrl.indexOf("callback=") > 0) throw new Error("Security error");
       conf = this.loaderInfo.parameters;
 
       // IE needs mouse / keyboard events
```
