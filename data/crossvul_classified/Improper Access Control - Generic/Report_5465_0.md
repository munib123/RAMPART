# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 5465_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5465_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1312-1352 of the vulnerable file.

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

		_isValidPath: function(path) {
			var sections = path.split('/');
			for (var i = 0; i < sections.length; i++) {
				if (sections[i] === '..') {
					return false;
				}
			}
			return true;
		},

		/**
		 * Sets the current directory name and updates the breadcrumb.
		 * @param targetDir directory to display
		 * @param changeUrl true to also update the URL, false otherwise (default)
		 */
		_setCurrentDir: function(targetDir, changeUrl) {
			targetDir = targetDir.replace(/\\/g, '/');
			if (!this._isValidPath(targetDir)) {
				targetDir = '/';
				changeUrl = true;
			}
			var previousDir = this.getCurrentDirectory(),
				baseDir = OC.basename(targetDir);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1329,8 +1329,15 @@
 
 		_isValidPath: function(path) {
 			var sections = path.split('/');
-			for (var i = 0; i < sections.length; i++) {
+			var i;
+			for (i = 0; i < sections.length; i++) {
 				if (sections[i] === '..') {
+					return false;
+				}
+			}
+			var specialChars = [decodeURIComponent('%00'), decodeURIComponent('%0A')];
+			for (i = 0; i < specialChars.length; i++) {
+				if (path.indexOf(specialChars[i]) !== -1) {
 					return false;
 				}
 			}
@@ -1345,6 +1352,7 @@
 		_setCurrentDir: function(targetDir, changeUrl) {
 			targetDir = targetDir.replace(/\\/g, '/');
 			if (!this._isValidPath(targetDir)) {
+				OC.Notification.showTemporary(t('files', 'Invalid path'));
 				targetDir = '/';
 				changeUrl = true;
 			}
@@ -1435,12 +1443,22 @@
 			this._currentFileModel = null;
 			this.$el.find('.select-all').prop('checked', false);
 			this.showMask();
-			this._reloadCall = this.filesClient.getFolderContents(
-				this.getCurrentDirectory(), {
-					includeParent: true,
-					properties: this._getWebdavProperties()
-				}
-			);
+			try {
+				this._reloadCall = this.filesClient.getFolderContents(
+					this.getCurrentDirectory(), {
+						includeParent: true,
+						properties: this._getWebdavProperties()
+					}
+				);
+			} catch (e) {
+				if (e instanceof DOMException) {
+					console.error(e);
+					this.changeDirectory('/');
+					OC.Notification.showTemporary(t('files', 'Invalid path'));
+					return;
+				}
+				throw e;
+			}
 			if (this._detailsView) {
 				// close sidebar
 				this._updateDetailsView(null);
@@ -1457,7 +1475,7 @@
 			}
 
 			// Firewall Blocked request?
-			if (status === 403) {
+			if (status === 403 || status === 400) {
 				// Go home
 				this.changeDirectory('/');
 				OC.Notification.showTemporary(t('files', 'This operation is forbidden'));
```
