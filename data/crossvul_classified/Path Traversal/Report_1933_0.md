# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 1933_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1933_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 288-328 of the vulnerable file.

        saveSettings = true;
        credentialSecretChanged = true;
    }

    if (this.missingFiles.indexOf('package.json') !== -1) {
        if (!data.files || !data.files.package) {
            // Cannot update a project that doesn't have a known package.json
            return Promise.reject("Cannot update project with missing package.json");
        }
    }

    if (data.hasOwnProperty('files')) {
        this.package['node-red'] = this.package['node-red'] || { settings: {}};
        if (data.files.hasOwnProperty('package') && (data.files.package !== fspath.join(this.paths.root,"package.json") || !this.paths['package.json'])) {
            // We have a package file. It could be one that doesn't exist yet,
            // or it does exist and we need to load it.
            if (!/package\.json$/.test(data.files.package)) {
                return Promise.reject("Invalid package file: "+data.files.package)
            }
            var root = data.files.package.substring(0,data.files.package.length-12);
            this.paths.root = root;
            this.paths['package.json'] = data.files.package;
            globalProjectSettings.projects[this.name].rootPath = root;
            saveSettings = true;
            // 1. check if it exists
            if (fs.existsSync(fspath.join(this.path,this.paths['package.json']))) {
                // Load the existing one....
            } else {
                var newPackage = defaultFileSet["package.json"](this);
                fs.writeFileSync(fspath.join(this.path,this.paths['package.json']),newPackage);
                this.package = JSON.parse(newPackage);
            }
            reloadProject = true;
            flowFilesChanged = true;
        }

        if (data.files.hasOwnProperty('flow') && this.package['node-red'].settings.flowFile !== data.files.flow.substring(this.paths.root.length)) {
            this.paths.flowFile = data.files.flow;
            this.package['node-red'].settings.flowFile = data.files.flow.substring(this.paths.root.length);
            savePackage = true;
            flowFilesChanged = true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -305,6 +305,9 @@
                 return Promise.reject("Invalid package file: "+data.files.package)
             }
             var root = data.files.package.substring(0,data.files.package.length-12);
+            if (/^\.\./.test(fspath.relative(this.path,fspath.join(this.path,data.files.package)))) {
+                return Promise.reject("Invalid package file: "+data.files.package)
+            }
             this.paths.root = root;
             this.paths['package.json'] = data.files.package;
             globalProjectSettings.projects[this.name].rootPath = root;
@@ -322,12 +325,18 @@
         }
 
         if (data.files.hasOwnProperty('flow') && this.package['node-red'].settings.flowFile !== data.files.flow.substring(this.paths.root.length)) {
+            if (/^\.\./.test(fspath.relative(this.path,fspath.join(this.path,data.files.flow)))) {
+                return Promise.reject("Invalid flow file: "+data.files.flow)
+            }
             this.paths.flowFile = data.files.flow;
             this.package['node-red'].settings.flowFile = data.files.flow.substring(this.paths.root.length);
             savePackage = true;
             flowFilesChanged = true;
         }
         if (data.files.hasOwnProperty('credentials') && this.package['node-red'].settings.credentialsFile !== data.files.credentials.substring(this.paths.root.length)) {
+            if (/^\.\./.test(fspath.relative(this.path,fspath.join(this.path,data.files.credentials)))) {
+                return Promise.reject("Invalid credentials file: "+data.files.credentials)
+            }
             this.paths.credentialsFile = data.files.credentials;
             this.package['node-red'].settings.credentialsFile = data.files.credentials.substring(this.paths.root.length);
             // Don't know if the credSecret is invalid or not so clear the flag
@@ -490,6 +499,10 @@
     if (treeish !== "_") {
         return gitTools.getFile(this.path, filePath, treeish);
     } else {
+        let fullPath = fspath.join(this.path,filePath);
+        if (/^\.\./.test(fspath.relative(this.path,fullPath))) {
+            throw new Error("Invalid file name")
+        }
         return fs.readFile(fspath.join(this.path,filePath),"utf8");
     }
 };
@@ -639,6 +652,11 @@
 
 Project.prototype.resolveMerge = function (file,resolutions) {
     var filePath = fspath.join(this.path,file);
+
+    if (/^\.\./.test(fspath.relative(this.path,filePath))) {
+        throw new Error("Invalid file name")
+    }
+
     var self = this;
     if (typeof resolutions === 'string') {
         return util.writeFile(filePath, resolutions).then(function() {
@@ -1062,7 +1080,7 @@
 function init(_settings, _runtime) {
     settings = _settings;
     runtime = _runtime;
-    projectsDir = fspath.join(settings.userDir,"projects");
+    projectsDir = fspath.resolve(fspath.join(settings.userDir,"projects"));
     authCache.init();
 }
 
```
