# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5287_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5287_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 127-168 of the vulnerable file.

				}
			}).fail(function () {
				OC.dialogs.alert(t('core', 'Error while changing permissions'),
					t('core', 'Error'));
			});
		},
		/**
		 *
		 * @param {String} itemType
		 * @param {String} path
		 * @param {String} appendTo
		 * @param {String} link
		 * @param {Number} possiblePermissions
		 * @param {String} filename
		 */
		showDropDown: function (itemType, path, appendTo, link, possiblePermissions, filename) {
			// This is a sync AJAX request on the main thread...
			var data = this._loadShares(path);
			var dropDownEl;
			var self = this;
			var html = '<div id="dropdown" class="drop shareDropDown" data-item-type="' + itemType +
				'" data-item-source="' + path + '">';
			if (data !== false && data[0] && !_.isUndefined(data[0].uid_file_owner) &&
				data[0].uid_file_owner !== OC.currentUser
			) {
				html += '<span class="reshare">';
				if (oc_config.enable_avatars === true) {
					html += '<div class="avatar"></div>';
				}

				if (data[0].share_type == this.SHARE_TYPE_GROUP) {
					html += t('core', 'Shared with you and the group {group} by {owner}', {
						group: data[0].share_with,
						owner: data[0].displayname_owner
					});
				} else {
					html += t('core', 'Shared with you by {owner}',
						{owner: data[0].displayname_owner});
				}
				html += '</span><br />';
				// reduce possible permissions to what the original share allowed
				possiblePermissions = possiblePermissions & data[0].permissions;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,8 +144,8 @@
 			var data = this._loadShares(path);
 			var dropDownEl;
 			var self = this;
-			var html = '<div id="dropdown" class="drop shareDropDown" data-item-type="' + itemType +
-				'" data-item-source="' + path + '">';
+			var html = '<div id="dropdown" class="drop shareDropDown" data-item-type="' + escapeHTML(itemType) +
+				'" data-item-source="' + escapeHTML(path) + '">';
 			if (data !== false && data[0] && !_.isUndefined(data[0].uid_file_owner) &&
 				data[0].uid_file_owner !== OC.currentUser
 			) {
```
