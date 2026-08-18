# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2821_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2821_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 14-54 of the vulnerable file.

	/vendor/bower-asset/jquery/dist/jquery.js;
	lib/tooltip;
	et2_core_DOMWidget;
*/

/**
 * Class which manages the DOM node itself. The simpleWidget class is derrived
 * from et2_DOMWidget and implements the getDOMNode function. A setDOMNode
 * function is provided, which attatches the given node to the DOM if possible.
 *
 * @augments et2_DOMWidget
 */
var et2_baseWidget = (function(){ "use strict"; return et2_DOMWidget.extend(et2_IAligned,
{
	attributes: {
		"statustext": {
			"name": "Tooltip",
			"type": "string",
			"description": "Tooltip which is shown for this element",
			"translate": true
		},
		"align": {
			"name": "Align",
			"type": "string",
			"default": "left",
			"description": "Position of this element in the parent hbox"
		},
		"onclick": {
			"name": "onclick",
			"type": "js",
			"default": et2_no_init,
			"description": "JS code which is executed when the element is clicked."
		}
	},

	/**
	 * Constructor
	 *
	 * @memberOf et2BaseWidget
	 */
	init: function() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,12 @@
 			"description": "Tooltip which is shown for this element",
 			"translate": true
 		},
+		"statustext_html": {
+			"name": "Tooltip is html",
+			"type": "boolean",
+			"description": "Flag to allow html content in tooltip",
+			"default": false
+		},
 		"align": {
 			"name": "Align",
 			"type": "string",
@@ -277,7 +283,7 @@
 
 			if (_value && _value != '')
 			{
-				this.egw().tooltipBind(elem, _value);
+				this.egw().tooltipBind(elem, _value, this.options.statustext_html);
 				this._tooltipElem = elem;
 			}
 		}
```
