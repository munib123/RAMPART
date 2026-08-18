# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 2079_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2079_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 32-72 of the vulnerable file.

    private var button:Sprite;

    // The text in the clipboard
    private var clipText:String = "";

    // AMD or CommonJS module ID/path to access the ZeroClipboard object
    private var jsModuleId:String = null;

    // constructor, setup event listeners and external interfaces
    public function ZeroClipboard() {

      // Align the stage to top left
      stage.align = "TL";
      stage.scaleMode = "noScale";

      // Get the flashvars
      var flashvars:Object = LoaderInfo( this.root.loaderInfo ).parameters;

      // Allow the SWF object to communicate with a page on a different origin than its own (e.g. SWF served from CDN)
      if (flashvars.trustedOrigins && typeof flashvars.trustedOrigins === "string") {
        var origins:Array = flashvars.trustedOrigins.split("\\").join("\\\\").split(",");
        flash.system.Security.allowDomain.apply(null, origins);
      }

      // Enable complete AMD (e.g. RequireJS) and CommonJS (e.g. Browserify) support
      if (flashvars.jsModuleId && typeof flashvars.jsModuleId === "string") {
        jsModuleId = flashvars.jsModuleId.split("\\").join("\\\\");
      }

      // invisible button covers entire stage
      button = new Sprite();
      button.buttonMode = true;
      button.useHandCursor = false;
      button.graphics.beginFill(0xCCFF00);
      button.graphics.drawRect(0, 0, stage.stageWidth, stage.stageHeight);
      button.alpha = 0.0;
      addChild(button);

      // Adding the event listeners
      button.addEventListener(MouseEvent.CLICK, mouseClick);
      button.addEventListener(MouseEvent.MOUSE_OVER, mouseOver);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,13 +49,13 @@
 
       // Allow the SWF object to communicate with a page on a different origin than its own (e.g. SWF served from CDN)
       if (flashvars.trustedOrigins && typeof flashvars.trustedOrigins === "string") {
-        var origins:Array = flashvars.trustedOrigins.split("\\").join("\\\\").split(",");
+        var origins:Array = ZeroClipboard.sanitizeString(flashvars.trustedOrigins).split(",");
         flash.system.Security.allowDomain.apply(null, origins);
       }
 
       // Enable complete AMD (e.g. RequireJS) and CommonJS (e.g. Browserify) support
       if (flashvars.jsModuleId && typeof flashvars.jsModuleId === "string") {
-        jsModuleId = flashvars.jsModuleId.split("\\").join("\\\\");
+        jsModuleId = ZeroClipboard.sanitizeString(flashvars.jsModuleId);
       }
 
       // invisible button covers entire stage
@@ -83,6 +83,16 @@
       dispatch("load", ZeroClipboard.metaData());
     }
 
+    // sanitizeString
+    //
+    // This private function will accept a string, and return a sanitized string
+    // to avoid XSS vulnerabilities
+    //
+    // returns an XSS safe String
+    private static function sanitizeString(dirty:String): String {
+      return dirty.replace(/\\/g,"\\\\")
+    }
+
     // mouseClick
     //
     // The mouseClick private function handles clearing the clipboard, and
@@ -99,7 +109,7 @@
 
       // signal to the page it is done
       dispatch("complete", ZeroClipboard.metaData(event, {
-        text: clipText.split("\\").join("\\\\")
+        text: ZeroClipboard.sanitizeString(clipText)
       }));
 
       // reset the text
```
