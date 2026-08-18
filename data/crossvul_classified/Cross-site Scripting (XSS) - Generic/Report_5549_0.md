# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 5549_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5549_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 60-100 of the vulnerable file.

		 */
		public function Plupload():void {
			if (stage)
				init();
			else
				addEventListener(Event.ADDED_TO_STAGE, init);
		}

		/**
		 * Initialization event handler.
		 *
		 * @param e Event object.
		 */
		private function init(e:Event = null):void {
			removeEventListener(Event.ADDED_TO_STAGE, init);

			// Allow cross domain scripting access
			// Security.allowDomain("*");

			// Setup id
			this.id = this.stage.loaderInfo.parameters["id"];

			// Setup file reference list
			this.fileRefList = new FileReferenceList();
			this.fileRefList.addEventListener(Event.CANCEL, cancelEvent);
			this.fileRefList.addEventListener(Event.SELECT, selectEvent);

			initSingleFileReference();

			this.files = new Dictionary();

			// Align and scale stage
			this.stage.align = StageAlign.TOP_LEFT;
			this.stage.scaleMode = StageScaleMode.NO_SCALE;

			// Add something to click on
			this.clickArea = new MovieClip();
			this.clickArea.graphics.beginFill(0x000000, 0); // Fill with transparent color
			this.clickArea.graphics.drawRect(0, 0, 1024, 1024);
			this.clickArea.x = 0;
			this.clickArea.y = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,7 +77,7 @@
 			// Security.allowDomain("*");
 
 			// Setup id
-			this.id = this.stage.loaderInfo.parameters["id"];
+			this.id = (this.stage.loaderInfo.parameters["id"]).toString().replace(/[^\w]/g, ''); // allow only [a-zA-Z0-9_]
 
 			// Setup file reference list
 			this.fileRefList = new FileReferenceList();
```
