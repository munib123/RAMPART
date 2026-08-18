# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 1588_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1588_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 128-168 of the vulnerable file.

    var statuss = responses.map(function (x) {return x[0];});
    var headerss = responses.map(function (x) {return x[1];});
    var contentss = responses.map(function (x) {return x[2];});
    callback(statuss, headerss, contentss);
  }
}

/**
 * creates the minifed javascript for the given minified name
 * @param req the Express request
 * @param res the Express response
 */
function minify(req, res, next)
{
  var filename = req.params['filename'];

  // No relative paths, especially if they may go up the file hierarchy.
  filename = path.normalize(path.join(ROOT_DIR, filename));
  if (filename.indexOf(ROOT_DIR) == 0) {
    filename = filename.slice(ROOT_DIR.length);
    filename = filename.replace(/\\/g, '/'); // Windows (safe generally?)
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -145,7 +145,6 @@
   filename = path.normalize(path.join(ROOT_DIR, filename));
   if (filename.indexOf(ROOT_DIR) == 0) {
     filename = filename.slice(ROOT_DIR.length);
-    filename = filename.replace(/\\/g, '/'); // Windows (safe generally?)
   } else {
     res.writeHead(404, {});
     res.end();
```
