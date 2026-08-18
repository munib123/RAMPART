# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 2547_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2547_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1079-1119 of the vulnerable file.

    function _typed(name, signatures) {
      var refs = new Refs();

      // parse signatures, expand them
      var _signatures = parseSignatures(signatures);
      if (_signatures.length == 0) {
        throw new Error('No signatures provided');
      }

      // filter all any type signatures
      var anys = filterAnyTypeSignatures(_signatures);

      // parse signatures into a node tree
      var node = parseTree(_signatures, [], anys);

      //var util = require('util');
      //console.log('ROOT');
      //console.log(util.inspect(node, { depth: null }));

      // generate code for the typed function
      var code = [];
      var _name = name || '';
      var _args = getArgs(maxParams(_signatures));
      code.push('function ' + _name + '(' + _args.join(', ') + ') {');
      code.push('  "use strict";');
      code.push('  var name = \'' + _name + '\';');
      code.push(node.toCode(refs, '  ', false));
      code.push('}');

      // generate body for the factory function
      var body = [
        refs.toCode(),
        'return ' + code.join('\n')
      ].join('\n');

      // evaluate the JavaScript code and attach function references
      var factory = (new Function(refs.name, 'createError', body));
      var fn = factory(refs, createError);

      //console.log('FN\n' + fn.toString()); // TODO: cleanup

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1096,12 +1096,15 @@
       //console.log(util.inspect(node, { depth: null }));
 
       // generate code for the typed function
+      // safeName is a conservative replacement of characters 
+      // to prevend being able to inject JS code at the place of the function name 
+      // the name is useful for stack trackes therefore we want have it there
       var code = [];
-      var _name = name || '';
-      var _args = getArgs(maxParams(_signatures));
-      code.push('function ' + _name + '(' + _args.join(', ') + ') {');
+      var safeName = (name || '').replace(/[^a-zA-Z0-9_$]/g, '_')
+      var args = getArgs(maxParams(_signatures));
+      code.push('function ' + safeName + '(' + args.join(', ') + ') {');
       code.push('  "use strict";');
-      code.push('  var name = \'' + _name + '\';');
+      code.push('  var name = ' + JSON.stringify(name || '') + ';');
       code.push(node.toCode(refs, '  ', false));
       code.push('}');
 
```
