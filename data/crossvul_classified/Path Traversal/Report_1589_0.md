# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 1589_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1589_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 148-188 of the vulnerable file.

  } else {
    res.writeHead(404, {});
    res.end();
    return; 
  }

  /* Handle static files for plugins/libraries:
     paths like "plugins/ep_myplugin/static/js/test.js"
     are rewritten into ROOT_PATH_OF_MYPLUGIN/static/js/test.js,
     commonly ETHERPAD_ROOT/node_modules/ep_myplugin/static/js/test.js
  */
  var match = filename.match(/^plugins\/([^\/]+)(\/(?:(static\/.*)|.*))?$/);
  if (match) {
    var library = match[1];
    var libraryPath = match[2] || '';

    if (plugins.plugins[library] && match[3]) {
      var plugin = plugins.plugins[library];
      var pluginPath = plugin.package.realPath;
      filename = path.relative(ROOT_DIR, pluginPath + libraryPath);
      filename = filename.replace(/\\/g, '/'); // Windows (safe generally?)
    } else if (LIBRARY_WHITELIST.indexOf(library) != -1) {
      // Go straight into node_modules
      // Avoid `require.resolve()`, since 'mustache' and 'mustache/index.js'
      // would end up resolving to logically distinct resources.
      filename = '../node_modules/' + library + libraryPath;
    }
  }

  // What content type should this be?
  // TODO: This should use a MIME module.
  var contentType;
  if (filename.match(/\.js$/)) {
    contentType = "text/javascript";
  } else if (filename.match(/\.css$/)) {
    contentType = "text/css";
  } else if (filename.match(/\.html$/)) {
    contentType = "text/html";
  } else if (filename.match(/\.txt$/)) {
    contentType = "text/plain";
  } else if (filename.match(/\.png$/)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,7 +165,6 @@
       var plugin = plugins.plugins[library];
       var pluginPath = plugin.package.realPath;
       filename = path.relative(ROOT_DIR, pluginPath + libraryPath);
-      filename = filename.replace(/\\/g, '/'); // Windows (safe generally?)
     } else if (LIBRARY_WHITELIST.indexOf(library) != -1) {
       // Go straight into node_modules
       // Avoid `require.resolve()`, since 'mustache' and 'mustache/index.js'
```
