# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4190_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4190_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 51-91 of the vulnerable file.

		function(xhr)
		{
			console.error(xhr);
		}
	);
}

$("#search").on("keyup", Delay(function()
{
	var value = $(this).val();
	if (value === "all")
	{
		value = "";
	}

	equipmentTable.search(value).draw();
}, 200));

$(document).on('click', '.equipment-delete-button', function(e)
{
	var objectName = $(e.currentTarget).attr('data-equipment-name');
	var objectId = $(e.currentTarget).attr('data-equipment-id');

	bootbox.confirm({
		message: __t('Are you sure to delete equipment "%s"?', objectName),
		closeButton: false,
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
		callback: function(result)
		{
			if (result === true)
			{
				Grocy.Api.Delete('objects/equipment/' + objectId, {},
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,7 +68,7 @@
 
 $(document).on('click', '.equipment-delete-button', function(e)
 {
-	var objectName = $(e.currentTarget).attr('data-equipment-name');
+	var objectName = SanitizeHtml($(e.currentTarget).attr('data-equipment-name'));
 	var objectId = $(e.currentTarget).attr('data-equipment-id');
 
 	bootbox.confirm({
```
