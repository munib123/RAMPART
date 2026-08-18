# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 2546_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2546_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 43-84 of the vulnerable file.

   * Compile the node to javascript code
   * @param {ObjectNode} node The node to be compiled
   * @param {Object} defs     Object which can be used to define functions
   *                          or constants globally available for the compiled
   *                          expression
   * @param {Object} args     Object with local function arguments, the key is
   *                          the name of the argument, and the value is `true`.
   *                          The object may not be mutated, but must be
   *                          extended instead.
   * @return {string} code
   * @private
   */
  function compileObjectNode(node, defs, args) {
    if (!(node instanceof ObjectNode)) {
      throw new TypeError('No valid ObjectNode')
    }

    var entries = [];
    for (var key in node.properties) {
      if (hasOwnProperty(node.properties, key)) {
        if (!isSafeProperty(node.properties, key)) {
          throw new Error('No access to property "' + key + '"');
        }

        entries.push(stringify(key) + ': ' + compile(node.properties[key], defs, args));
      }
    }
    return '{' + entries.join(', ') + '}';
  }

  // register the compile function
  register(ObjectNode.prototype.type, compileObjectNode);

  /**
   * Execute a callback for each of the child nodes of this node
   * @param {function(child: Node, path: string, parent: Node)} callback
   */
  ObjectNode.prototype.forEach = function (callback) {
    for (var key in this.properties) {
      if (this.properties.hasOwnProperty(key)) {
        callback(this.properties[key], 'properties[' + stringify(key) + ']', this);
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,11 +60,15 @@
     var entries = [];
     for (var key in node.properties) {
       if (hasOwnProperty(node.properties, key)) {
-        if (!isSafeProperty(node.properties, key)) {
-          throw new Error('No access to property "' + key + '"');
+        // we stringify/parse the key here to resolve unicode characters,
+        // so you cannot create a key like {"co\\u006Estructor": null} 
+        var stringifiedKey = stringify(key)
+        var parsedKey = JSON.parse(stringifiedKey)
+        if (!isSafeProperty(node.properties, parsedKey)) {
+          throw new Error('No access to property "' + parsedKey + '"');
         }
 
-        entries.push(stringify(key) + ': ' + compile(node.properties[key], defs, args));
+        entries.push(stringifiedKey + ': ' + compile(node.properties[key], defs, args));
       }
     }
     return '{' + entries.join(', ') + '}';
```
