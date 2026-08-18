# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 1933_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1933_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 93-133 of the vulnerable file.

            gitTools.init(_settings).then(function(gitConfig) {
                if (!gitConfig || /^1\./.test(gitConfig.version)) {
                    if (!gitConfig) {
                        projectLogMessages.push(log._("storage.localfilesystem.projects.git-not-found"))
                    } else {
                        projectLogMessages.push(log._("storage.localfilesystem.projects.git-version-old",{version:gitConfig.version}))
                    }
                    projectsEnabled = false;
                    try {
                        // As projects have to be turned on, we know this property
                        // must exist at this point, so turn it off.
                        // TODO: when on-by-default, this will need to do more
                        // work to disable.
                        settings.editorTheme.projects.enabled = false;
                    } catch(err) {
                    }
                } else {
                    globalGitUser = gitConfig.user;
                    Projects.init(settings,runtime);
                    sshTools.init(settings);
                    projectsDir = fspath.join(settings.userDir,"projects");
                    if (!settings.readOnly) {
                        return fs.ensureDir(projectsDir)
                        //TODO: this is accessing settings from storage directly as settings
                        //      has not yet been initialised. That isn't ideal - can this be deferred?
                        .then(storageSettings.getSettings)
                        .then(function(globalSettings) {
                            var saveSettings = false;
                            if (!globalSettings.projects) {
                                globalSettings.projects = {
                                    projects: {}
                                }
                                saveSettings = true;
                            } else {
                                activeProject = globalSettings.projects.activeProject;
                            }
                            if (!globalSettings.projects.projects) {
                                globalSettings.projects.projects = {};
                                saveSettings = true;
                            }
                            if (settings.flowFile) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,7 @@
                     globalGitUser = gitConfig.user;
                     Projects.init(settings,runtime);
                     sshTools.init(settings);
-                    projectsDir = fspath.join(settings.userDir,"projects");
+                    projectsDir = fspath.resolve(fspath.join(settings.userDir,"projects"));
                     if (!settings.readOnly) {
                         return fs.ensureDir(projectsDir)
                         //TODO: this is accessing settings from storage directly as settings
@@ -207,9 +207,16 @@
 }
 
 function loadProject(name) {
+    let fullPath = fspath.resolve(fspath.join(projectsDir,name));
     var projectPath = name;
     if (projectPath.indexOf(fspath.sep) === -1) {
-        projectPath = fspath.join(projectsDir,name);
+        projectPath = fullPath;
+    } else {
+        // Ensure this project dir is under projectsDir;
+        let relativePath = fspath.relative(projectsDir,fullPath);
+        if (/^\.\./.test(relativePath)) {
+            throw new Error("Invalid project name")
+        }
     }
     return Projects.load(projectPath).then(function(project) {
         activeProject = project;
@@ -234,6 +241,10 @@
         throw e;
     }
     var projectPath = fspath.join(projectsDir,name);
+    let relativePath = fspath.relative(projectsDir,projectPath);
+    if (/^\.\./.test(relativePath)) {
+        throw new Error("Invalid project name")
+    }
     return Projects.delete(user, projectPath);
 }
 
@@ -392,6 +403,10 @@
         metadata.files.credentialSecret = currentEncryptionKey;
     }
     metadata.path = fspath.join(projectsDir,metadata.name);
+    if (/^\.\./.test(fspath.relative(projectsDir,metadata.path))) {
+        throw new Error("Invalid project name")
+    }
+
     return Projects.create(user, metadata).then(function(p) {
         return setActiveProject(user, p.name);
     }).then(function() {
```
