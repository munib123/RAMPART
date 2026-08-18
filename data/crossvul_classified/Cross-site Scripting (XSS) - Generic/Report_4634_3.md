# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4634_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4634_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-21 of the vulnerable file.

const inlineSvgFonts = require('./font-inliner');
const SvgElement = require('./svg-element');
const convertFonts = require('./font-converter');
const fixupSvgString = require('./fixup-svg-string');
const transformStrokeWidths = require('./transform-applier');

/**
 * Main quirks-mode SVG rendering code.
 */
class SvgRenderer {
    /**
     * Create a quirks-mode SVG renderer for a particular canvas.
     * @param {HTMLCanvasElement} [canvas] An optional canvas element to draw to. If this is not provided, the renderer
     * will create a new canvas.
     * @constructor
     */
    constructor (canvas) {
        this._canvas = canvas || document.createElement('canvas');
        this._context = this._canvas.getContext('2d');
        this._measurements = {x: 0, y: 0, width: 0, height: 0};
        this._cachedImage = null;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
+const DOMPurify = require('dompurify');
 const inlineSvgFonts = require('./font-inliner');
 const SvgElement = require('./svg-element');
 const convertFonts = require('./font-converter');
@@ -363,19 +364,31 @@
         // which returns the full bounding-box of all drawn SVG
         // elements, similar to how Scratch 2.0 did measurement.
         const svgSpot = document.createElement('span');
-        // Clone the svg tag. This tag becomes unusable/undrawable in browsers
-        // once it's appended to the page, perhaps for security reasons?
-        const tempTag = this._svgTag.cloneNode(/* deep */ true);
+        // Since we're adding user-provided SVG to document.body,
+        // sanitizing is required. This should not affect bounding box calculation.
+        // outerHTML is attribute of Element (and not HTMLElement), so use it instead of
+        // calling serializer or toString()
+        // NOTE: this._svgTag remains untouched!
+        const rawValue = this._svgTag.outerHTML;
+        const sanitizedValue = DOMPurify.sanitize(rawValue, {
+            // Use SVG profile (no HTML elements)
+            USE_PROFILES: {svg: true},
+            // Remove some tags that Scratch does not use.
+            FORBID_TAGS: ['a', 'audio', 'canvas', 'video'],
+            // Allow data URI in image tags (e.g. SVGs converted from bitmap)
+            ADD_DATA_URI_TAGS: ['image']
+        });
         let bbox;
         try {
-            svgSpot.appendChild(tempTag);
+            // Insert sanitized value.
+            svgSpot.innerHTML = sanitizedValue;
             document.body.appendChild(svgSpot);
-            // Take the bounding box.
-            bbox = tempTag.getBBox();
+            // Take the bounding box. We have to get elements via svgSpot
+            // because we added it via innerHTML.
+            bbox = svgSpot.children[0].getBBox();
         } finally {
             // Always destroy the element, even if, for example, getBBox throws.
             document.body.removeChild(svgSpot);
-            svgSpot.removeChild(tempTag);
         }
 
         // Enlarge the bbox from the largest found stroke width
```
