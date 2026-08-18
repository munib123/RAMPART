# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4190_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4190_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 4-44 of the vulnerable file.

		{ 'orderable': false, 'targets': 0 },
		{ 'searchable': false, "targets": 0 }
	],
});
$('#batteries-table tbody').removeClass("d-none");
batteriesTable.columns.adjust().draw();

$("#search").on("keyup", Delay(function()
{
	var value = $(this).val();
	if (value === "all")
	{
		value = "";
	}

	batteriesTable.search(value).draw();
}, 200));

$(document).on('click', '.battery-delete-button', function(e)
{
	var objectName = $(e.currentTarget).attr('data-battery-name');
	var objectId = $(e.currentTarget).attr('data-battery-id');

	bootbox.confirm({
		message: __t('Are you sure to delete battery "%s"?', objectName),
		buttons: {
			confirm: {
				label: __t('Yes'),
				className: 'btn-success'
			},
			cancel: {
				label: __t('No'),
				className: 'btn-danger'
			}
		},
		closeButton: false,
		callback: function(result)
		{
			if (result === true)
			{
				Grocy.Api.Delete('objects/batteries/' + objectId, {},
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,7 +21,7 @@
 
 $(document).on('click', '.battery-delete-button', function(e)
 {
-	var objectName = $(e.currentTarget).attr('data-battery-name');
+	var objectName = SanitizeHtml($(e.currentTarget).attr('data-battery-name'));
 	var objectId = $(e.currentTarget).attr('data-battery-id');
 
 	bootbox.confirm({
```
