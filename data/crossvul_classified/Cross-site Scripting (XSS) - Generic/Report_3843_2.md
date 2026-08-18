# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in actionscript
**Pair ID:** 3843_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** actionscript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3843_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```actionscript
Lines 69-109 of the vulnerable file.

    }

    // mouseClick
    //
    // The mouseClick private function handles clearing the clipboard, and
    // setting new clip text. It gets this from the clipText private variable.
    // Once the text has been placed in the clipboard, It then signals to the
    // Javascript that it is done.
    //
    // returns nothing
    private function mouseClick(event:MouseEvent): void {

      // Clear the current text from the clipboard
      Clipboard.generalClipboard.clear();

      // set the clipboard data from the variable
      Clipboard.generalClipboard.setData(clipFormat, clipText);

      // signal to the page it is done
      ExternalInterface.call( 'ZeroClipboard.dispatch', 'complete',  metaData(event, {
        text: clipText,
        format: clipFormat
      }));
    }

    // mouseOver
    //
    // The mouseOver function signals to the page that the button is being hovered.
    //
    // returns nothing
    private function mouseOver(event:MouseEvent): void {
      ExternalInterface.call( 'ZeroClipboard.dispatch', 'mouseOver', metaData(event) );
    }

    // mouseOut
    //
    // The mouseOut function signals to the page that the button is not being hovered.
    //
    // returns nothing
    private function mouseOut(event:MouseEvent): void {
      ExternalInterface.call( 'ZeroClipboard.dispatch', 'mouseOut', metaData(event) );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,7 +86,7 @@
 
       // signal to the page it is done
       ExternalInterface.call( 'ZeroClipboard.dispatch', 'complete',  metaData(event, {
-        text: clipText,
+        text: clipText.split("\\").join("\\\\"),
         format: clipFormat
       }));
     }
```
