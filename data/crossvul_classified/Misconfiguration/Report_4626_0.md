# CrossVul Fix Pair: Initialization of a Resource with an Insecure Default in javascript
**Pair ID:** 4626_0
**Vulnerability Class:** Misconfiguration
**CWE:** CWE-1188
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4626_0`)

## Vulnerability Information & PoC

## Description
Initialization of a Resource with an Insecure Default - Developers often choose default values that leave the product as open and easy to use as possible out-of-the-box, under the assumption that the administrator can (or should) change the default value.

## Vulnerable Code
```javascript
Lines 224-264 of the vulnerable file.

    throw grunt.util.error('Unable to read "' + filepath + '" file (Error code: ' + e.code + ').', e);
  }
};

// Read a file, parse its contents, return an object.
file.readJSON = function(filepath, options) {
  var src = file.read(filepath, options);
  var result;
  grunt.verbose.write('Parsing ' + filepath + '...');
  try {
    result = JSON.parse(src);
    grunt.verbose.ok();
    return result;
  } catch (e) {
    grunt.verbose.error();
    throw grunt.util.error('Unable to parse "' + filepath + '" file (' + e.message + ').', e);
  }
};

// Read a YAML file, parse its contents, return an object.
file.readYAML = function(filepath, options) {
  var src = file.read(filepath, options);
  var result;
  grunt.verbose.write('Parsing ' + filepath + '...');
  try {
    result = YAML.load(src);
    grunt.verbose.ok();
    return result;
  } catch (e) {
    grunt.verbose.error();
    throw grunt.util.error('Unable to parse "' + filepath + '" file (' + e.message + ').', e);
  }
};

// Write a file.
file.write = function(filepath, contents, options) {
  if (!options) { options = {}; }
  var nowrite = grunt.option('no-write');
  grunt.verbose.write((nowrite ? 'Not actually writing ' : 'Writing ') + filepath + '...');
  // Create path, if necessary.
  file.mkdir(path.dirname(filepath));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -241,12 +241,21 @@
 };
 
 // Read a YAML file, parse its contents, return an object.
-file.readYAML = function(filepath, options) {
+file.readYAML = function(filepath, options, yamlOptions) {
+  if (!options) { options = {}; }
+  if (!yamlOptions) { yamlOptions = {}; }
+
   var src = file.read(filepath, options);
   var result;
   grunt.verbose.write('Parsing ' + filepath + '...');
   try {
-    result = YAML.load(src);
+    // use the recommended way of reading YAML files
+    // https://github.com/nodeca/js-yaml#safeload-string---options-
+    if (yamlOptions.unsafeLoad) {
+      result = YAML.load(src);
+    } else {
+      result = YAML.safeLoad(src);
+    }
     grunt.verbose.ok();
     return result;
   } catch (e) {
```
