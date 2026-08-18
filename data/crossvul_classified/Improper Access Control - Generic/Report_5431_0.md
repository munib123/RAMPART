# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 5431_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5431_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1452-1492 of the vulnerable file.

				// Go home
				this.changeDirectory('/');
				OC.Notification.showTemporary(
					t('files', 'This directory is unavailable, please check the logs or contact the administrator')
				);
				return false;
			}

			if (status === 503) {
				// Go home
				if (this.getCurrentDirectory() !== '/') {
					this.changeDirectory('/');
					// TODO: read error message from exception
					OC.Notification.showTemporary(
						t('files', 'Storage not available')
					);
				}
				return false;
			}

			if (status === 404) {
				// go back home
				this.changeDirectory('/');
				return false;
			}
			// aborted ?
			if (status === 0){
				return true;
			}

			// TODO: parse remaining quota from PROPFIND response
			this.updateStorageStatistics(true);

			// first entry is the root
			this.dirInfo = result.shift();

			if (this.dirInfo.permissions) {
				this.setDirectoryPermissions(this.dirInfo.permissions);
			}

			result.sort(this._sortComparator);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1469,7 +1469,7 @@
 				return false;
 			}
 
-			if (status === 404) {
+			if (status === 404 || status === 405) {
 				// go back home
 				this.changeDirectory('/');
 				return false;
```
