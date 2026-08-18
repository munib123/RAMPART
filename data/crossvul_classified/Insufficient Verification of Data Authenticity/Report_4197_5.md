# CrossVul Fix Pair: Insufficient Verification of Data Authenticity in javascript
**Pair ID:** 4197_5
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-345
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4197_5`)

## Vulnerability Information & PoC

## Description
Insufficient Verification of Data Authenticity - The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Vulnerable Code
```javascript
Lines 1-30 of the vulnerable file.

/**
 * Copyright (c) 2015-present, Waysact Pty Ltd
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

var Template = require('webpack/lib/Template');
var util = require('./util');

function WebIntegrityJsonpMainTemplatePlugin(sriPlugin, compilation) {
  this.sriPlugin = sriPlugin;
  this.compilation = compilation;
}

WebIntegrityJsonpMainTemplatePlugin.prototype.addSriHashes =
  function addSriHashes(mainTemplate, source, chunk) {
    var allChunks = util.findChunks(chunk);
    var includedChunks = chunk.getChunkMaps().hash;
    var hashFuncNames = this.sriPlugin.options.hashFuncNames;

    if (Object.keys(includedChunks).length > 0) {
      return (Template.asString || mainTemplate.asString)([
        source,
        '__webpack_require__.sriHashes = ' +
          JSON.stringify(
            Array.from(allChunks).reduce(function chunkIdReducer(
              sriHashes,
              depChunk
            ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,10 @@
 
 var Template = require('webpack/lib/Template');
 var util = require('./util');
+var webpackVersionComponents = require('webpack/package.json').version.split(
+  '.'
+);
+var webpackVersionMajor = Number(webpackVersionComponents[0]);
 
 function WebIntegrityJsonpMainTemplatePlugin(sriPlugin, compilation) {
   this.sriPlugin = sriPlugin;
@@ -47,7 +51,7 @@
  *  Patch jsonp-script code to add the integrity attribute.
  */
 WebIntegrityJsonpMainTemplatePlugin.prototype.addAttribute =
-  function addAttribute(mainTemplate, elName, source, chunk) {
+  function addAttribute(mainTemplate, elName, source) {
     const outputOptions = this.compilation.outputOptions || mainTemplate.outputOptions;
     if (!outputOptions.crossOriginLoading) {
       this.sriPlugin.errorOnce(
@@ -55,9 +59,12 @@
         'webpack option output.crossOriginLoading not set, code splitting will not work!'
       );
     }
+
     return (Template.asString || mainTemplate.asString)([
       source,
-      elName + '.integrity = __webpack_require__.sriHashes[' + (chunk ? `'${chunk.id}'` : 'chunkId') + '];',
+      elName + '.integrity = __webpack_require__.sriHashes[' +
+        ((webpackVersionMajor >= 5 && elName === 'script') ? 'key.match(/^chunk-([0-9]+)$/)[1]' : 'chunkId') +
+        '];',
       elName + '.crossOrigin = ' + JSON.stringify(outputOptions.crossOriginLoading) + ';',
     ]);
   };
```
