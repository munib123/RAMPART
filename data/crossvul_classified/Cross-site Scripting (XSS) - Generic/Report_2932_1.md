# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2932_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2932_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 2041-2081 of the vulnerable file.

	} else {
		if (servercounter == 0) {
			summaryservers = "data marked with this sharing group will not be pushed.";
		}
	}
	$('#summarylocal').text(summaryorgs);
	$('#summarylocalextend').text(summaryextendorgs);
	$('#summaryexternal').text(remotesummaryorgs);
	$('#summaryexternalextend').text(remotesummaryextendorgs);
	$('#summaryservers').text(summaryservers);
}

function sharingGroupPopulateOrganisations() {
	$('input[id=SharingGroupOrganisations]').val(JSON.stringify(organisations));
	$('.orgRow').remove();
	var id = 0;
	var html = '';
	organisations.forEach(function(org) {
		html = '<tr id="orgRow' + id + '" class="orgRow">';
		html += '<td class="short">' + org.type + '&nbsp;</td>';
		html += '<td>' + org.name + '&nbsp;</td>';
		html += '<td>' + org.uuid + '&nbsp;</td>';
		html += '<td class="short" style="text-align:center;">';
		if (org.removable == 1) {
			html += '<input id="orgExtend' + id + '" type="checkbox" onClick="sharingGroupExtendOrg(' + id + ')" ';
			if (org.extend) html+= 'checked';
			html += '></input>';
		} else {
			html += '<span class="icon-ok"></span>'
		}
		html +='</td>';
		html += '<td class="actions short">';
		if (org.removable == 1) html += '<span class="icon-trash" onClick="sharingGroupRemoveOrganisation(' + id + ')"></span>';
		html += '&nbsp;</td></tr>';
		$('#organisations_table tr:last').after(html);
		id++;
	});
}

function sharingGroupPopulateServers() {
	$('input[id=SharingGroupServers]').val(JSON.stringify(servers));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2058,7 +2058,7 @@
 	organisations.forEach(function(org) {
 		html = '<tr id="orgRow' + id + '" class="orgRow">';
 		html += '<td class="short">' + org.type + '&nbsp;</td>';
-		html += '<td>' + org.name + '&nbsp;</td>';
+		html += '<td>' + $('<div>').text(org.name).html() + '&nbsp;</td>';
 		html += '<td>' + org.uuid + '&nbsp;</td>';
 		html += '<td class="short" style="text-align:center;">';
 		if (org.removable == 1) {
```
