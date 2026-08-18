# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 4634_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4634_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 10-50 of the vulnerable file.

        #reference {
            display:inline-block;
            font-size:0;
        }
        .column {
            display:inline-block;
        }
    </style>
</head>
<body>
    <p>
        <input type="file" id="svg-file-upload", accept="image/svg+xml">
    </p>
    <p>
        <label for="render-scale">Scale:</label>
        <input type="range" style="width:50%;" id="render-scale" value="1" min="0.5" max="3" step="any">
        <label for="render-scale" id="scale-display"></label>
    </p>
    <p>
        <input type="button" id="trigger-render" value="Render">
    </p>

    <div class="columns">
        <div class="column">
            <div>Rendered Result</div>
            <canvas id="render-canvas" class="result"></canvas>
       </div>
       <div class="column">
            <div>Reference</div>
            <span id="reference"></span>
       </div>
     </div>

    <script src="scratch-svg-renderer.js"></script>
    <script>
        const renderCanvas = document.getElementById("render-canvas");
        const referenceImage = document.getElementById("reference");
        const fileChooser = document.getElementById("svg-file-upload");
        const scaleSlider = document.getElementById("render-scale");
        const scaleDisplay = document.getElementById("scale-display");
        const renderButton = document.getElementById("trigger-render");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,10 @@
     </p>
     <p>
         <input type="button" id="trigger-render" value="Render">
+        <label for="shouldRenderReference">
+          <input type="checkbox" id="shouldRenderReference" checked />
+          Render Reference?
+        </label>
     </p>
 
     <div class="columns">
@@ -37,6 +41,17 @@
        <div class="column">
             <div>Reference</div>
             <span id="reference"></span>
+       </div>
+     </div>
+    <div class="columns">
+        <div class="column">
+            <div>Rendered Content</div>
+            <textarea id="renderedContent" wrap="off" cols="50" rows="50"></textarea>
+       </div>
+       <div class="column">
+            <div>Reference</div>
+            <span id="reference"></span>
+            <textarea id="referenceContent" wrap="off" cols="50" rows="50"></textarea>
        </div>
      </div>
 
@@ -59,7 +74,8 @@
 
         function renderSVGString(str) {
             renderer.fromString(str);
-            renderer._draw(parseFloat(scaleSlider.value));
+            renderer._draw(parseFloat(scaleSlider.value), ()=>{});
+            renderedContent.value = renderer.toString(true);
         }
 
         function updateReferenceImage() {
@@ -92,7 +108,8 @@
 
         function renderLoadedString() {
             renderSVGString(loadedSVGString);
-            updateReferenceImage();
+            referenceContent.value = loadedSVGString;
+            shouldRenderReference.checked && updateReferenceImage();
         }
 
         function scaleSliderChanged() {
```
