# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4108_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4108_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 41-81 of the vulnerable file.

				'url': '//www.youtube.com/embed/',
				'html': '<iframe width="560" height="315" src="{url}" frameborder="0" data-mybb-vt="{type}" data-mybb-vsrc="{src}"></iframe>'
			},
			'Twitch': {
				'match': /twitch\.tv\/(?:[\w+_-]+)\/v\/(\d+)/,
				'url': '//player.twitch.tv/?video=v',
				'html': '<iframe src="{url}" frameborder="0" scrolling="no" height="378" width="620" data-mybb-vt="{type}" data-mybb-vsrc="{src}"></iframe>'
			}
		}
	};

	// Add custom MyBB CSS
	$('<style type="text/css">' +
		'.sceditor-dropdown { text-align: ' + ($('body').css('direction') === 'rtl' ? 'right' : 'left') + '; }' +
		'</style>').appendTo('body');

	// Update editor to use align= as alignment
	$.sceditor.formats.bbcode
		.set('align', {
			html: function (element, attrs, content) {
				return '<div align="' + (attrs.defaultattr || 'left') + '">' + content + '</div>';
			},
			isInline: false
		});
	$.each(mybbCmd.align, function (i, val) {
		$.sceditor.formats.bbcode.set(val, {
			format: '[align=' + val + ']{0}[/align]'
		});
		$.sceditor.command
			.set(val, {
				txtExec: ['[align=' + val + ']', '[/align]']
			});
	});

	// Update font to support MyBB's BBCode dialect
	$.sceditor.formats.bbcode
		.set('list', {
			html: function (element, attrs, content) {
				var type = (attrs.defaultattr === '1' ? 'ol' : 'ul');

				if (attrs.defaultattr === 'a')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,7 +58,7 @@
 	$.sceditor.formats.bbcode
 		.set('align', {
 			html: function (element, attrs, content) {
-				return '<div align="' + (attrs.defaultattr || 'left') + '">' + content + '</div>';
+				return '<div align="' + ($.sceditor.escapeEntities(attrs.defaultattr) || 'left') + '">' + content + '</div>';
 			},
 			isInline: false
 		});
@@ -168,7 +168,7 @@
 			if (size < 0) {
 				size = 0;
 			}
-			return '<font data-scefontsize="' + attrs.defaultattr + '" size="' + size + '">' + content + '</font>';
+			return '<font data-scefontsize="' + $.sceditor.escapeEntities(attrs.defaultattr) + '" size="' + size + '">' + content + '</font>';
 		}
 	});
 
@@ -218,7 +218,6 @@
 			var author = '',
 				$elm = $(element),
 				$cite = $elm.children('cite').first();
-			$cite.html($cite.text());
 
 			if ($cite.length === 1 || $elm.data('author')) {
 				author = $cite.text() || $elm.data('author');
@@ -244,13 +243,13 @@
 			var data = '';
 
 			if (attrs.pid)
-				data += ' data-pid="' + attrs.pid + '"';
+				data += ' data-pid="' + $.sceditor.escapeEntities(attrs.pid) + '"';
 
 			if (attrs.dateline)
-				data += ' data-dateline="' + attrs.dateline + '"';
+				data += ' data-dateline="' + $.sceditor.escapeEntities(attrs.dateline) + '"';
 
 			if (typeof attrs.defaultattr !== "undefined")
-				content = '<cite>' + attrs.defaultattr.replace(/ /g, '&nbsp;') + '</cite>' + content;
+				content = '<cite>' + $.sceditor.escapeEntities(attrs.defaultattr).replace(/ /g, '&nbsp;') + '</cite>' + content;
 
 			return '<blockquote' + data + '>' + content + '</blockquote>';
 		},
@@ -280,7 +279,7 @@
 		html: function (token, attrs, content) {
 			if (typeof attrs.defaultattr == 'string' && attrs.defaultattr != '' && attrs.defaultattr != '{defaultattr}') {
 				return '<font face="' +
-					attrs.defaultattr +
+					$.sceditor.escapeEntities(attrs.defaultattr) +
 					'">' + content + '</font>';
 			} else {
 				return content;
```
