# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 5464_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5464_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1383-1423 of the vulnerable file.

		});
		it('switches dir and fetches file list when calling changeDirectory()', function() {
			fileList.changeDirectory('/anothersubdir');
			expect(fileList.getCurrentDirectory()).toEqual('/anothersubdir');
			expect(getFolderContentsStub.calledOnce).toEqual(true);
			expect(getFolderContentsStub.calledWith('/anothersubdir')).toEqual(true);
		});
		it('converts backslashes to slashes when calling changeDirectory()', function() {
			fileList.changeDirectory('/another\\subdir');
			expect(fileList.getCurrentDirectory()).toEqual('/another/subdir');
		});
		it('switches to root dir when current directory is invalid', function() {
			_.each([
				'..',
				'/..',
				'../',
				'/../',
				'/../abc',
				'/abc/..',
				'/abc/../',
				'/../abc/'
			], function(path) {
				fileList.changeDirectory(path);
				expect(fileList.getCurrentDirectory()).toEqual('/');
			});
		});
		it('allows paths with dotdot at the beginning or end', function() {
			_.each([
				'/..abc',
				'/def..',
				'/...'
			], function(path) {
				fileList.changeDirectory(path);
				expect(fileList.getCurrentDirectory()).toEqual(path);
			});
		});
		it('switches to root dir when current directory does not exist', function() {
			fileList.changeDirectory('/unexist');
			deferredList.reject(404);
			expect(fileList.getCurrentDirectory()).toEqual('/');
		});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1400,7 +1400,9 @@
 				'/../abc',
 				'/abc/..',
 				'/abc/../',
-				'/../abc/'
+				'/../abc/',
+				'/zero' + decodeURIComponent('%00') + 'byte/',
+				'/really who adds new' + decodeURIComponent('%0A') + 'lines in their paths/',
 			], function(path) {
 				fileList.changeDirectory(path);
 				expect(fileList.getCurrentDirectory()).toEqual('/');
@@ -1415,6 +1417,12 @@
 				fileList.changeDirectory(path);
 				expect(fileList.getCurrentDirectory()).toEqual(path);
 			});
+		});
+		it('switches to root dir in case of bad request', function() {
+			fileList.changeDirectory('/unexist');
+			// can happen in case of invalid chars in the URL
+			deferredList.reject(400);
+			expect(fileList.getCurrentDirectory()).toEqual('/');
 		});
 		it('switches to root dir when current directory does not exist', function() {
 			fileList.changeDirectory('/unexist');
```
