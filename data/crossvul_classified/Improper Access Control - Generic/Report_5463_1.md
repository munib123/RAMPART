# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 5463_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5463_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1362-1402 of the vulnerable file.

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
				'/../abc/',
				'/another\\subdir/../foo\\../bar\\..\\file/..\\folder/../'
			], function(path) {
				fileList.changeDirectory(path);
				expect(fileList.getCurrentDirectory()).toEqual('/');
			});
		});
		it('allows paths with dotdot at the beginning or end', function() {
			_.each([
				'/..abc',
				'/def..',
				'/...',
				'/abc../def'
			], function(path) {
				fileList.changeDirectory(path);
				expect(fileList.getCurrentDirectory()).toEqual(path);
			});
		});
		it('switches to root dir when current directory does not exist', function() {
			fileList.changeDirectory('/unexist');
			deferredList.reject(404);
			expect(fileList.getCurrentDirectory()).toEqual('/');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1379,9 +1379,10 @@
 				'/abc/..',
 				'/abc/../',
 				'/../abc/',
+				'/foo%0Abar/',
 				'/another\\subdir/../foo\\../bar\\..\\file/..\\folder/../'
 			], function(path) {
-				fileList.changeDirectory(path);
+				fileList.changeDirectory(decodeURI(path));
 				expect(fileList.getCurrentDirectory()).toEqual('/');
 			});
 		});
```
