# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4190_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4190_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 546-586 of the vulnerable file.

	{
		event.preventDefault();

		if (document.getElementById("add-recipe-form").checkValidity() === false) //There is at least one validation error
		{
			return false;
		}
		else
		{
			$("#save-add-recipe-button").click();
		}
	}
});

$(document).on('click', '.recipe-order-missing-button', function(e)
{
	// Remove the focus from the current button
	// to prevent that the tooltip stays until clicked anywhere else
	document.activeElement.blur();

	var objectName = $(e.currentTarget).attr('data-recipe-name');
	var objectId = $(e.currentTarget).attr('data-recipe-id');
	var button = $(this);
	var servings = $(e.currentTarget).attr('data-mealplan-servings');

	bootbox.confirm({
		message: __t('Are you sure to put all missing ingredients for recipe "%s" on the shopping list?', objectName),
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -563,7 +563,7 @@
 	// to prevent that the tooltip stays until clicked anywhere else
 	document.activeElement.blur();
 
-	var objectName = $(e.currentTarget).attr('data-recipe-name');
+	var objectName = SanitizeHtml($(e.currentTarget).attr('data-recipe-name'));
 	var objectId = $(e.currentTarget).attr('data-recipe-id');
 	var button = $(this);
 	var servings = $(e.currentTarget).attr('data-mealplan-servings');
@@ -667,7 +667,7 @@
 	// to prevent that the tooltip stays until clicked anywhere else
 	document.activeElement.blur();
 
-	var objectName = $(e.currentTarget).attr('data-recipe-name');
+	var objectName = SanitizeHtml($(e.currentTarget).attr('data-recipe-name'));
 	var objectId = $(e.currentTarget).attr('data-recipe-id');
 	var servings = $(e.currentTarget).attr('data-mealplan-servings');
 
```
