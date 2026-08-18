# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4508_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4508_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-23 of the vulnerable file.

define([
	"require",
	"dojo/_base/declare", // declare
	"dojo/dom-attr", // domAttr.get
	"dojo/keys", // keys.ENTER
	"dojo/_base/lang", // lang.delegate lang.hitch lang.trim
	"dojo/on",
	"dojo/sniff", // has("ie")
	"dojo/query", // query
	"dojo/string", // string.substitute
	"../_Plugin",
	"../../form/DropDownButton",
	"../range"
], function(require, declare, domAttr, keys, lang, on, has, query, string,
	_Plugin, DropDownButton, rangeapi){

	// module:
	//		dijit/_editor/plugins/LinkDialog

	var LinkDialog = declare("dijit._editor.plugins.LinkDialog", _Plugin, {
		// summary:
		//		This plugin provides the basis for an 'anchor' (link) dialog and an extension of it
		//		provides the image link dialog.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 define([
 	"require",
+	"dojo/_base/array",
 	"dojo/_base/declare", // declare
 	"dojo/dom-attr", // domAttr.get
 	"dojo/keys", // keys.ENTER
@@ -11,7 +12,7 @@
 	"../_Plugin",
 	"../../form/DropDownButton",
 	"../range"
-], function(require, declare, domAttr, keys, lang, on, has, query, string,
+], function(require, array, declare, domAttr, keys, lang, on, has, query, string,
 	_Plugin, DropDownButton, rangeapi){
 
 	// module:
@@ -25,6 +26,21 @@
 		//		The command provided by this plugin is:
 		//
 		//		- createLink
+
+		// allowUnsafeHtml: boolean
+		//		If false (default), the link description will be filtered to prevent HTML content.
+		//		If true no filtering is done, allowing for HTML content within the link element.
+		//		The filter can be specified with the 'linkFilter' option.
+		allowUnsafeHtml: false,
+
+		// linkFilter: function or array of replacement pairs
+		//		If 'allowUnsafeHtml' is false then this filter will be applied to the link Description value.
+		//		function: the function will be invoked with the string value of the Description field and its
+		//			return value will be used
+		//		array: each array item should be an array of two values to pass to String#replace
+		linkFilter: [
+			[/</g, "&lt;"]
+		],
 
 		// Override _Plugin.buttonClass.   This plugin is controlled by a DropDownButton
 		// (which triggers a TooltipDialog).
@@ -252,6 +268,16 @@
 			if(args && args.urlInput){
 				args.urlInput = args.urlInput.replace(/"/g, "&quot;");
 			}
+			if(!this.allowUnsafeHtml && args && args.textInput){
+				if(typeof this.linkFilter === 'function'){
+					args.textInput = this.linkFilter(args.textInput);
+				}
+				else{
+					array.forEach(this.linkFilter, function (currentFilter) {
+						args.textInput = args.textInput.replace(currentFilter[0], currentFilter[1]);
+					});
+				}
+			}
 			return args;
 		},
 
@@ -629,8 +655,15 @@
 	});
 
 	// Register these plugins
-	_Plugin.registry["createLink"] = function(){
-		return new LinkDialog({command: "createLink"});
+	_Plugin.registry["createLink"] = function(args){
+		var pluginOptions = {
+			command: "createLink",
+			allowUnsafeHtml: ("allowUnsafeHtml" in args) ? args.allowUnsafeHtml : false
+		};
+		if("linkFilter" in args){
+			pluginOptions.linkFilter = args.linkFilter;
+		}
+		return new LinkDialog(pluginOptions);
 	};
 	_Plugin.registry["insertImage"] = function(){
 		return new ImgLinkDialog({command: "insertImage"});
```
