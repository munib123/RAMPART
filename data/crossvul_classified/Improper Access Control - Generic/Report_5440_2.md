# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 5440_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5440_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 22-62 of the vulnerable file.

		var version1 = new VersionModel({
			id: time1,
			timestamp: time1,
			name: 'some file.txt',
			size: 140,
			fullPath: '/subdir/some file.txt'
		});
		var version2 = new VersionModel({
			id: time2,
			timestamp: time2,
			name: 'some file.txt',
			size: 150,
			fullPath: '/subdir/some file.txt'
		});

		testVersions = [version1, version2];

		fetchStub = sinon.stub(VersionCollection.prototype, 'fetch');
		fileInfoModel = new OCA.Files.FileInfoModel({
			id: 123,
			name: 'test.txt'
		});
		tabView = new VersionsTabView();
		tabView.render();
	});

	afterEach(function() {
		fetchStub.restore();
		tabView.remove();
		clock.restore();
	});

	describe('rendering', function() {
		it('reloads matching versions when setting file info model', function() {
			tabView.setFileInfo(fileInfoModel);
			expect(fetchStub.calledOnce).toEqual(true);
		});

		it('renders loading icon while fetching versions', function() {
			tabView.setFileInfo(fileInfoModel);
			tabView.collection.trigger('request');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,8 @@
 		fetchStub = sinon.stub(VersionCollection.prototype, 'fetch');
 		fileInfoModel = new OCA.Files.FileInfoModel({
 			id: 123,
-			name: 'test.txt'
+			name: 'test.txt',
+			permissions: OC.PERMISSION_READ | OC.PERMISSION_UPDATE
 		});
 		tabView = new VersionsTabView();
 		tabView.render();
@@ -86,12 +87,37 @@
 			expect($item.find('.revertVersion').length).toEqual(1);
 			expect($item.find('.preview').attr('src')).toEqual(version2.getPreviewUrl());
 		});
+
+		it('does not render revert button when no update permissions', function() {
+
+			fileInfoModel.set('permissions', OC.PERMISSION_READ);
+			tabView.setFileInfo(fileInfoModel);
+			tabView.collection.set(testVersions);
+
+			var version1 = testVersions[0];
+			var version2 = testVersions[1];
+			var $versions = tabView.$el.find('.versions>li');
+			expect($versions.length).toEqual(2);
+			var $item = $versions.eq(0);
+			expect($item.find('.downloadVersion').attr('href')).toEqual(version1.getDownloadUrl());
+			expect($item.find('.versiondate').text()).toEqual('seconds ago');
+			expect($item.find('.revertVersion').length).toEqual(0);
+			expect($item.find('.preview').attr('src')).toEqual(version1.getPreviewUrl());
+
+			$item = $versions.eq(1);
+			expect($item.find('.downloadVersion').attr('href')).toEqual(version2.getDownloadUrl());
+			expect($item.find('.versiondate').text()).toEqual('2 days ago');
+			expect($item.find('.revertVersion').length).toEqual(0);
+			expect($item.find('.preview').attr('src')).toEqual(version2.getPreviewUrl());
+		});
 	});
 
 	describe('More versions', function() {
 		var hasMoreResultsStub;
 
 		beforeEach(function() {
+			tabView.setFileInfo(fileInfoModel);
+			fetchStub.reset();
 			tabView.collection.set(testVersions);
 			hasMoreResultsStub = sinon.stub(VersionCollection.prototype, 'hasMoreResults');
 		});
```
