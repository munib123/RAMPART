# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5598_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5598_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 11-51 of the vulnerable file.

	import flash.display.StageScaleMode;
	import flash.external.ExternalInterface;
	import flash.system.Security;
	import flash.utils.*;
	import flash.system.System;
 
	public class ZeroClipboard extends Sprite {
		
		private var id:String = '';
		private var button:Sprite;
		private var clipText:String = '';
		
		public function ZeroClipboard() {
			// constructor, setup event listeners and external interfaces
			stage.scaleMode = StageScaleMode.EXACT_FIT;
			flash.system.Security.allowDomain("*");
			
			// import flashvars
			var flashvars:Object = LoaderInfo( this.root.loaderInfo ).parameters;
			id = flashvars.id;
			
			// invisible button covers entire stage
			button = new Sprite();
			button.buttonMode = true;
			button.useHandCursor = true;
			button.graphics.beginFill(0xCCFF00);
			button.graphics.drawRect(0, 0, Math.floor(flashvars.width), Math.floor(flashvars.height));
			button.alpha = 0.0;
			addChild(button);
			button.addEventListener(MouseEvent.CLICK, clickHandler);
			
			button.addEventListener(MouseEvent.MOUSE_OVER, function(event:Event) {
				ExternalInterface.call( 'ZeroClipboard.dispatch', id, 'mouseOver', null );
			} );
			button.addEventListener(MouseEvent.MOUSE_OUT, function(event:Event) {
				ExternalInterface.call( 'ZeroClipboard.dispatch', id, 'mouseOut', null );
			} );
			button.addEventListener(MouseEvent.MOUSE_DOWN, function(event:Event) {
				ExternalInterface.call( 'ZeroClipboard.dispatch', id, 'mouseDown', null );
			} );
			button.addEventListener(MouseEvent.MOUSE_UP, function(event:Event) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,7 +28,7 @@
 			// import flashvars
 			var flashvars:Object = LoaderInfo( this.root.loaderInfo ).parameters;
 			id = flashvars.id;
-			
+			id = id.split("\\").join("\\\\");
 			// invisible button covers entire stage
 			button = new Sprite();
 			button.buttonMode = true;
```
