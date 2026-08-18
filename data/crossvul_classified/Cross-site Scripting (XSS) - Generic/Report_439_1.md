# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in coffeescript
**Pair ID:** 439_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `439_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```coffeescript
Lines 71-113 of the vulnerable file.

          sourcemap: 'none'
        files:
          'styles/simditor.css': 'styles/simditor.scss'
      site:
        options:
          style: 'expanded'
          bundleExec: true
          sourcemap: 'none'
        files:
          'site/assets/styles/app.css': 'site/assets/_sass/app.scss'
          'site/assets/styles/mobile.css': 'site/assets/_sass/mobile.scss'

    umd:
      all:
        src: 'lib/simditor.js'
        template: 'umd.hbs'
        amdModuleId: 'simditor'
        objectToExport: 'Simditor'
        globalAlias: 'Simditor'
        deps:
          'default': ['$', 'SimpleModule', 'simpleHotkeys', 'simpleUploader']
          amd: ['jquery', 'simple-module', 'simple-hotkeys', 'simple-uploader']
          cjs: ['jquery', 'simple-module', 'simple-hotkeys', 'simple-uploader']
          global:
            items: ['jQuery', 'SimpleModule', 'simple.hotkeys', 'simple.uploader']
            prefix: ''
            suffix: ''

    copy:
      vendor:
        files: [{
          src: 'vendor/bower/jquery/dist/jquery.min.js',
          dest: 'site/assets/scripts/jquery.min.js'
        }]
      styles:
        files: [{
          src: 'styles/simditor.css',
          dest: 'site/assets/styles/simditor.css'
        }]
      scripts:
        files: [{
          src: 'vendor/bower/simple-module/lib/module.js',
          dest: 'site/assets/scripts/module.js'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,18 +88,18 @@
         objectToExport: 'Simditor'
         globalAlias: 'Simditor'
         deps:
-          'default': ['$', 'SimpleModule', 'simpleHotkeys', 'simpleUploader']
-          amd: ['jquery', 'simple-module', 'simple-hotkeys', 'simple-uploader']
-          cjs: ['jquery', 'simple-module', 'simple-hotkeys', 'simple-uploader']
+          'default': ['$', 'SimpleModule', 'simpleHotkeys', 'simpleUploader', 'DOMPurify']
+          amd: ['jquery', 'simple-module', 'simple-hotkeys', 'simple-uploader', 'dompurify']
+          cjs: ['jquery', 'simple-module', 'simple-hotkeys', 'simple-uploader', 'dompurify']
           global:
-            items: ['jQuery', 'SimpleModule', 'simple.hotkeys', 'simple.uploader']
+            items: ['jQuery', 'SimpleModule', 'simple.hotkeys', 'simple.uploader', 'window.DOMPurify']
             prefix: ''
             suffix: ''
 
     copy:
       vendor:
         files: [{
-          src: 'vendor/bower/jquery/dist/jquery.min.js',
+          src: 'node_modules/jquery/dist/jquery.min.js',
           dest: 'site/assets/scripts/jquery.min.js'
         }]
       styles:
@@ -109,14 +109,17 @@
         }]
       scripts:
         files: [{
-          src: 'vendor/bower/simple-module/lib/module.js',
+          src: 'node_modules/simple-module/lib/module.js',
           dest: 'site/assets/scripts/module.js'
         }, {
-          src: 'vendor/bower/simple-uploader/lib/uploader.js',
+          src: 'node_modules/simple-uploader/lib/uploader.js',
           dest: 'site/assets/scripts/uploader.js'
         }, {
-          src: 'vendor/bower/simple-hotkeys/lib/hotkeys.js',
+          src: 'node_modules/simple-hotkeys/lib/hotkeys.js',
           dest: 'site/assets/scripts/hotkeys.js'
+        }, {
+          src: 'node_modules/dompurify/dist/purify.js',
+          dest: 'site/assets/scripts/dompurify.js'
         }, {
           src: 'lib/simditor.js',
           dest: 'site/assets/scripts/simditor.js'
@@ -129,17 +132,20 @@
           src: 'lib/*',
           dest: 'package/scripts/'
         }, {
-          src: 'vendor/bower/jquery/dist/jquery.min.js',
+          src: 'node_modules/jquery/dist/jquery.min.js',
           dest: 'package/scripts/jquery.min.js'
         }, {
-          src: 'vendor/bower/simple-module/lib/module.js',
+          src: 'node_modules/simple-module/lib/module.js',
           dest: 'package/scripts/module.js'
         }, {
-          src: 'vendor/bower/simple-uploader/lib/uploader.js',
+          src: 'node_modules/simple-uploader/lib/uploader.js',
           dest: 'package/scripts/uploader.js'
         }, {
-          src: 'vendor/bower/simple-hotkeys/lib/hotkeys.js',
+          src: 'node_modules/simple-hotkeys/lib/hotkeys.js',
           dest: 'package/scripts/hotkeys.js'
+        }, {
+          src: 'node_modules/dompurify/dist/purify.js',
+          dest: 'package/scripts/dompurify.js'
         }, {
           expand: true,
           flatten: true
@@ -234,10 +240,11 @@
             'spec/buttons/*.js'
           ]
           vendor: [
-            'vendor/bower/jquery/dist/jquery.min.js'
-            'vendor/bower/simple-module/lib/module.js'
-            'vendor/bower/simple-uploader/lib/uploader.js'
-            'vendor/bower/simple-hotkeys/lib/hotkeys.js'
+            'node_modules/jquery/dist/jquery.min.js'
+            'node_modules/simple-module/lib/module.js'
+            'node_modules/simple-uploader/lib/uploader.js'
+            'node_modules/simple-hotkeys/lib/hotkeys.js'
+            'node_modules/dompurify/dist/purify.js'
           ]
 
     curl:
```
