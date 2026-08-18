# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 1955_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1955_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 39-79 of the vulnerable file.

  return constantinople.toConstant(src, {pug: runtime, pug_interp: undefined});
}

/**
 * Initialize `Compiler` with the given `node`.
 *
 * @param {Node} node
 * @param {Object} options
 * @api public
 */

function Compiler(node, options) {
  this.options = options = options || {};
  this.node = node;
  this.bufferedConcatenationCount = 0;
  this.hasCompiledDoctype = false;
  this.hasCompiledTag = false;
  this.pp = options.pretty || false;
  if (this.pp && typeof this.pp !== 'string') {
    this.pp = '  ';
  }
  this.debug = false !== options.compileDebug;
  this.indents = 0;
  this.parentIndents = 0;
  this.terse = false;
  this.mixins = {};
  this.dynamicMixins = false;
  this.eachCount = 0;
  if (options.doctype) this.setDoctype(options.doctype);
  this.runtimeFunctionsUsed = [];
  this.inlineRuntimeFunctions = options.inlineRuntimeFunctions || false;
  if (this.debug && this.inlineRuntimeFunctions) {
    this.runtimeFunctionsUsed.push('rethrow');
  }
}

/**
 * Compiler prototype.
 */

Compiler.prototype = {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,11 @@
   this.pp = options.pretty || false;
   if (this.pp && typeof this.pp !== 'string') {
     this.pp = '  ';
+  }
+  if (this.pp && !/^\s+$/.test(this.pp)) {
+    throw new Error(
+      'The pretty parameter should either be a boolean or whitespace only string'
+    );
   }
   this.debug = false !== options.compileDebug;
   this.indents = 0;
@@ -452,7 +457,9 @@
   visitMixinBlock: function(block) {
     if (this.pp)
       this.buf.push(
-        "pug_indent.push('" + Array(this.indents + 1).join(this.pp) + "');"
+        'pug_indent.push(' +
+          stringify(Array(this.indents + 1).join(this.pp)) +
+          ');'
       );
     this.buf.push('block && block();');
     if (this.pp) this.buf.push('pug_indent.pop();');
@@ -504,7 +511,9 @@
       this.mixins[key].used = true;
       if (pp)
         this.buf.push(
-          "pug_indent.push('" + Array(this.indents + 1).join(pp) + "');"
+          'pug_indent.push(' +
+            stringify(Array(this.indents + 1).join(pp)) +
+            ');'
         );
       if (block || attrs.length || attrsBlocks.length) {
         this.buf.push(name + '.call({');
```
