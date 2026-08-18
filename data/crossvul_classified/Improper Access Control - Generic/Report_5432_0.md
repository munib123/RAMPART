# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 5432_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5432_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1310-1350 of the vulnerable file.

		 * @param {boolean} force set to true to force changing directory
		 */
		changeDirectory: function(targetDir, changeUrl, force) {
			var self = this;
			var currentDir = this.getCurrentDirectory();
			targetDir = targetDir || '/';
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1327,6 +1327,16 @@
 			return OC.linkTo('files', 'index.php')+"?dir="+ encodeURIComponent(dir).replace(/%2F/g, '/');
 		},
 
+		_isValidPath: function(path) {
+			var sections = path.split('/');
+			for (var i = 0; i < sections.length; i++) {
+				if (sections[i] === '..') {
+					return false;
+				}
+			}
+			return true;
+		},
+
 		/**
 		 * Sets the current directory name and updates the breadcrumb.
 		 * @param targetDir directory to display
@@ -1334,6 +1344,10 @@
 		 */
 		_setCurrentDir: function(targetDir, changeUrl) {
 			targetDir = targetDir.replace(/\\/g, '/');
+			if (!this._isValidPath(targetDir)) {
+				targetDir = '/';
+				changeUrl = true;
+			}
 			var previousDir = this.getCurrentDirectory(),
 				baseDir = OC.basename(targetDir);
 
```
