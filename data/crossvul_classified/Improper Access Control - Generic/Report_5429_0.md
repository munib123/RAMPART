# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 5429_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5429_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1316-1356 of the vulnerable file.

			if (!force && currentDir === targetDir) {
				return;
			}
			this._setCurrentDir(targetDir, changeUrl);
			this.reload().then(function(success){
				if (!success) {
					self.changeDirectory(currentDir, true);
				}
			});
		},
		linkTo: function(dir) {
			return OC.linkTo('files', 'index.php')+"?dir="+ encodeURIComponent(dir).replace(/%2F/g, '/');
		},

		/**
		 * Sets the current directory name and updates the breadcrumb.
		 * @param targetDir directory to display
		 * @param changeUrl true to also update the URL, false otherwise (default)
		 */
		_setCurrentDir: function(targetDir, changeUrl) {
			targetDir = targetDir.replace(/\\/g, '/');
			var previousDir = this.getCurrentDirectory(),
				baseDir = OC.basename(targetDir);

			if (baseDir !== '') {
				this.setPageTitle(baseDir);
			}
			else {
				this.setPageTitle();
			}

			this._currentDirectory = targetDir;

			// legacy stuff
			this.$el.find('#dir').val(targetDir);

			if (changeUrl !== false) {
				this.$el.trigger(jQuery.Event('changeDirectory', {
					dir: targetDir,
					previousDir: previousDir
				}));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1333,7 +1333,7 @@
 		 * @param changeUrl true to also update the URL, false otherwise (default)
 		 */
 		_setCurrentDir: function(targetDir, changeUrl) {
-			targetDir = targetDir.replace(/\\/g, '/');
+			targetDir = targetDir.replace(/\\/g, '/').replace(/\.\.\//g, '');
 			var previousDir = this.getCurrentDirectory(),
 				baseDir = OC.basename(targetDir);
 
```
