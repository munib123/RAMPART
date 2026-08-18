# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3902_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3902_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 15-61 of the vulnerable file.

	"./manipulation/support",

	"./data/var/dataPriv",
	"./data/var/dataUser",
	"./data/var/acceptData",
	"./core/DOMEval",
	"./core/nodeName",

	"./core/init",
	"./traversing",
	"./selector",
	"./event"
], function( jQuery, isAttached, flat, isFunction, push, rcheckableType,
	access, rtagName, rscriptType,
	wrapMap, getAll, setGlobalEval, buildFragment, support,
	dataPriv, dataUser, acceptData, DOMEval, nodeName ) {

"use strict";

var

	/* eslint-disable max-len */

	// See https://github.com/eslint/eslint/issues/3229
	rxhtmlTag = /<(?!area|br|col|embed|hr|img|input|link|meta|param)(([a-z][^\/\0>\x20\t\r\n\f]*)[^>]*)\/>/gi,

	/* eslint-enable */

	// Support: IE <=10 - 11, Edge 12 - 13 only
	// In IE/Edge using regex groups here causes severe slowdowns.
	// See https://connect.microsoft.com/IE/feedback/details/1736512/
	rnoInnerhtml = /<script|<style|<link/i,

	// checked="checked" or checked
	rchecked = /checked\s*(?:[^=]|=\s*.checked.)/i,
	rcleanScript = /^\s*<!(?:\[CDATA\[|--)|(?:\]\]|--)>\s*$/g;

// Prefer a tbody over its parent table for containing new rows
function manipulationTarget( elem, content ) {
	if ( nodeName( elem, "table" ) &&
		nodeName( content.nodeType !== 11 ? content : content.firstChild, "tr" ) ) {

		return jQuery( elem ).children( "tbody" )[ 0 ] || elem;
	}

	return elem;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,13 +33,6 @@
 
 var
 
-	/* eslint-disable max-len */
-
-	// See https://github.com/eslint/eslint/issues/3229
-	rxhtmlTag = /<(?!area|br|col|embed|hr|img|input|link|meta|param)(([a-z][^\/\0>\x20\t\r\n\f]*)[^>]*)\/>/gi,
-
-	/* eslint-enable */
-
 	// Support: IE <=10 - 11, Edge 12 - 13 only
 	// In IE/Edge using regex groups here causes severe slowdowns.
 	// See https://connect.microsoft.com/IE/feedback/details/1736512/
@@ -236,7 +229,7 @@
 
 jQuery.extend( {
 	htmlPrefilter: function( html ) {
-		return html.replace( rxhtmlTag, "<$1></$2>" );
+		return html;
 	},
 
 	clone: function( elem, dataAndEvents, deepDataAndEvents ) {
```
