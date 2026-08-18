# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 5441_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5441_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1-38 of the vulnerable file.

/*
 * Copyright (c) 2015
 *
 * This file is licensed under the Affero General Public License version 3
 * or later.
 *
 * See the COPYING-README file.
 *
 */

(function() {
	var TEMPLATE_ITEM =
		'<li data-revision="{{timestamp}}">' +
		'<img class="preview" src="{{previewUrl}}"/>' +
		'<a href="{{downloadUrl}}" class="downloadVersion"><img src="{{downloadIconUrl}}" />' +
		'<span class="versiondate has-tooltip" title="{{formattedTimestamp}}">{{relativeTimestamp}}</span>' +
		'</a>' +
		'<a href="#" class="revertVersion" title="{{revertLabel}}"><img src="{{revertIconUrl}}" /></a>' +
		'</li>';

	var TEMPLATE =
		'<ul class="versions"></ul>' +
		'<div class="clear-float"></div>' +
		'<div class="empty hidden">{{emptyResultLabel}}</div>' +
		'<input type="button" class="showMoreVersions hidden" value="{{moreVersionsLabel}}"' +
		' name="show-more-versions" id="show-more-versions" />' +
		'<div class="loading hidden" style="height: 50px"></div>';

	/**
	 * @memberof OCA.Versions
	 */
	var VersionsTabView = OCA.Files.DetailTabView.extend(
		/** @lends OCA.Versions.VersionsTabView.prototype */ {
		id: 'versionsTabView',
		className: 'tab versionsTabView',

		_template: null,

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,7 +15,9 @@
 		'<a href="{{downloadUrl}}" class="downloadVersion"><img src="{{downloadIconUrl}}" />' +
 		'<span class="versiondate has-tooltip" title="{{formattedTimestamp}}">{{relativeTimestamp}}</span>' +
 		'</a>' +
+		'{{#canRevert}}' +
 		'<a href="#" class="revertVersion" title="{{revertLabel}}"><img src="{{revertIconUrl}}" /></a>' +
+		'{{/canRevert}}' +
 		'</li>';
 
 	var TEMPLATE =
@@ -109,6 +111,9 @@
 				},
 
 				error: function() {
+					fileInfoModel.trigger('busy', fileInfoModel, false);
+					self.$el.find('.versions').removeClass('hidden');
+					self._toggleLoading(false);
 					OC.Notification.showTemporary(
 						t('files_version', 'Failed to revert {file} to revision {timestamp}.', {
 							file: versionModel.getFullPath(),
@@ -183,6 +188,7 @@
 				revertIconUrl: OC.imagePath('core', 'actions/history'),
 				previewUrl: version.getPreviewUrl(),
 				revertLabel: t('files_versions', 'Restore'),
+				canRevert: (this.collection.getFileInfo().get('permissions') & OC.PERMISSION_UPDATE) !== 0
 			}, version.attributes);
 		},
 
```
