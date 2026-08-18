# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3795_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3795_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 28-68 of the vulnerable file.

				if (($('#dropdown').length > 0) && $('#dropdown').hasClass('drop-versions') ) {
					if (file != $('#dropdown').data('file')) {
						$('#dropdown').hide('blind', function() {
							$('#dropdown').remove();
							$('tr').removeClass('mouseOver');
							createVersionsDropdown(filename, file);
						});
					}
				} else {
					createVersionsDropdown(filename, file);
				}
			}
		);
	}
});

function createVersionsDropdown(filename, files) {

	var historyUrl = OC.linkTo('files_versions', 'history.php') + '?path='+encodeURIComponent( $( '#dir' ).val() ).replace( /%2F/g, '/' )+'/'+encodeURIComponent( filename );

	var html = '<div id="dropdown" class="drop drop-versions" data-file="'+files+'">';
	html += '<div id="private">';
	html += '<select data-placeholder="Saved versions" id="found_versions" class="chzen-select" style="width:16em;">';
	html += '<option value=""></option>';
	html += '</select>';
	html += '</div>';
	html += '<input type="button" value="All versions..." onclick="window.location=\''+historyUrl+'\'" name="makelink" id="makelink" />';
	html += '<input id="link" style="display:none; width:90%;" />';

	if (filename) {
		$('tr').filterAttr('data-file',filename).addClass('mouseOver');
		$(html).appendTo($('tr').filterAttr('data-file',filename).find('td.filename'));
	} else {
		$(html).appendTo($('thead .share'));
	}

	$.ajax({
		type: 'GET',
		url: OC.filePath('files_versions', 'ajax', 'getVersions.php'),
		dataType: 'json',
		data: { source: files },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,7 +45,7 @@
 
 	var historyUrl = OC.linkTo('files_versions', 'history.php') + '?path='+encodeURIComponent( $( '#dir' ).val() ).replace( /%2F/g, '/' )+'/'+encodeURIComponent( filename );
 
-	var html = '<div id="dropdown" class="drop drop-versions" data-file="'+files+'">';
+	var html = '<div id="dropdown" class="drop drop-versions" data-file="'+escapeHTML(files)+'">';
 	html += '<div id="private">';
 	html += '<select data-placeholder="Saved versions" id="found_versions" class="chzen-select" style="width:16em;">';
 	html += '<option value=""></option>';
```
