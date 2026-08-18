# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 5431_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5431_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1319-1359 of the vulnerable file.

			expect(getFolderContentsStub.calledOnce).toEqual(true);
			expect(getFolderContentsStub.calledWith('/anothersubdir')).toEqual(true);
		});
		it('converts backslashes to slashes when calling changeDirectory()', function() {
			fileList.changeDirectory('/another\\subdir');
			expect(fileList.getCurrentDirectory()).toEqual('/another/subdir');
		});
		it('converts backslashes to slashes and removes traversals when calling changeDirectory()', function() {
			fileList.changeDirectory('/another\\subdir/../foo\\../bar\\..\\file/..\\folder/../');
			expect(fileList.getCurrentDirectory()).toEqual('/another/subdir/foo/bar/file/folder/');
		});
		it('does not convert folders with a ".." in the name', function() {
			fileList.changeDirectory('/abc../def');
			expect(fileList.getCurrentDirectory()).toEqual('/abc../def');
		});
		it('switches to root dir when current directory does not exist', function() {
			fileList.changeDirectory('/unexist');
			deferredList.reject(404);
			expect(fileList.getCurrentDirectory()).toEqual('/');
		});
		it('switches to root dir when current directory is forbidden', function() {
			fileList.changeDirectory('/unexist');
			deferredList.reject(403);
			expect(fileList.getCurrentDirectory()).toEqual('/');
		});
		it('switches to root dir when current directory is unavailable', function() {
			fileList.changeDirectory('/unexist');
			deferredList.reject(500);
			expect(fileList.getCurrentDirectory()).toEqual('/');
		});
		it('shows mask before loading file list then hides it at the end', function() {
			var showMaskStub = sinon.stub(fileList, 'showMask');
			var hideMaskStub = sinon.stub(fileList, 'hideMask');
			fileList.changeDirectory('/anothersubdir');
			expect(showMaskStub.calledOnce).toEqual(true);
			expect(hideMaskStub.calledOnce).toEqual(false);
			deferredList.resolve(200, [testRoot].concat(testFiles));
			expect(showMaskStub.calledOnce).toEqual(true);
			expect(hideMaskStub.calledOnce).toEqual(true);
			showMaskStub.restore();
			hideMaskStub.restore();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1336,6 +1336,11 @@
 			deferredList.reject(404);
 			expect(fileList.getCurrentDirectory()).toEqual('/');
 		});
+		it('switches to root dir when current directory returns 405', function() {
+			fileList.changeDirectory('/unexist');
+			deferredList.reject(405);
+			expect(fileList.getCurrentDirectory()).toEqual('/');
+		});
 		it('switches to root dir when current directory is forbidden', function() {
 			fileList.changeDirectory('/unexist');
 			deferredList.reject(403);
```
