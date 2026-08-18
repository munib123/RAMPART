# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1739_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1739_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 73-122 of the vulnerable file.

    
    Editor.prototype.load = function() {
        /** load the file */
        var that = this;
        var cm = this.codemirror;
        return this.contents.get(this.file_path, {type: 'file', format: 'text'})
            .then(function(model) {
                cm.setValue(model.content);

                // Setting the file's initial value creates a history entry,
                // which we don't want.
                cm.clearHistory();
                that._set_mode_for_model(model);
                that.save_enabled = true;
                that.generation = cm.changeGeneration();
                that.events.trigger("file_loaded.Editor", model);
                that._clean_state();
            }).catch(
            function(error) {
                that.events.trigger("file_load_failed.Editor", error);
                if (((error.xhr||{}).responseJSON||{}).reason === 'bad format') {
                    window.location = utils.url_path_join(
                        that.base_url,
                        'files',
                        that.file_path
                    );
                } else {
                    console.warn('Error while loading: the error was:')
                    console.warn(error)
                }
                cm.setValue("Error! " + error.message +
                                "\nSaving disabled.\nSee Console for more details.");
                cm.setOption('readOnly','nocursor')
                that.save_enabled = false;
            }
        );
    };

    Editor.prototype._set_mode_for_model = function (model) {
        /** Set the CodeMirror mode based on the file model */

        // Find and load the highlighting mode,
        // first by mime-type, then by file extension

        var modeinfo;
        // mimetype is unset on file rename
        if (model.mimetype) {
            modeinfo = CodeMirror.findModeByMIME(model.mimetype);
        }
        if (!modeinfo || modeinfo.mode === "null") {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,19 +90,10 @@
             }).catch(
             function(error) {
                 that.events.trigger("file_load_failed.Editor", error);
-                if (((error.xhr||{}).responseJSON||{}).reason === 'bad format') {
-                    window.location = utils.url_path_join(
-                        that.base_url,
-                        'files',
-                        that.file_path
-                    );
-                } else {
-                    console.warn('Error while loading: the error was:')
-                    console.warn(error)
-                }
+                console.warn('Error loading: ', error);
                 cm.setValue("Error! " + error.message +
                                 "\nSaving disabled.\nSee Console for more details.");
-                cm.setOption('readOnly','nocursor')
+                cm.setOption('readOnly','nocursor');
                 that.save_enabled = false;
             }
         );
@@ -186,7 +177,7 @@
     Editor.prototype._clean_state = function(){
         var clean = this.codemirror.isClean(this.generation);
         if (clean === this.clean){
-            return
+            return;
         } else {
             this.clean = clean;
         }
```
