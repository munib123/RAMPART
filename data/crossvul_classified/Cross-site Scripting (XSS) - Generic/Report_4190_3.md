# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4190_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4190_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 145-185 of the vulnerable file.

		$('#product_id').trigger('change');
	}
	else
	{
		if (Grocy.Components.ProductPicker.PopupOpen === true)
		{
			return;
		}

		var optionElement = $("#product_id option:contains(\"" + input + "\")").first();
		if (input.length > 0 && optionElement.length === 0 && typeof GetUriParam('addbarcodetoselection') === "undefined" && Grocy.Components.ProductPicker.GetPicker().parent().data('disallow-all-product-workflows').toString() === "false")
		{
			var addProductWorkflowsAdditionalCssClasses = "";
			if (Grocy.Components.ProductPicker.GetPicker().parent().data('disallow-add-product-workflows').toString() === "true")
			{
				addProductWorkflowsAdditionalCssClasses = "d-none";
			}

			Grocy.Components.ProductPicker.PopupOpen = true;
			bootbox.dialog({
				message: __t('"%s" could not be resolved to a product, how do you want to proceed?', input),
				title: __t('Create or assign product'),
				onEscape: function()
				{
					Grocy.Components.ProductPicker.PopupOpen = false;
					Grocy.Components.ProductPicker.SetValue('');
				},
				size: 'large',
				backdrop: true,
				closeButton: false,
				buttons: {
					cancel: {
						label: __t('Cancel'),
						className: 'btn-secondary responsive-button',
						callback: function()
						{
							Grocy.Components.ProductPicker.PopupOpen = false;
							Grocy.Components.ProductPicker.SetValue('');
						}
					},
					addnewproduct: {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -162,7 +162,7 @@
 
 			Grocy.Components.ProductPicker.PopupOpen = true;
 			bootbox.dialog({
-				message: __t('"%s" could not be resolved to a product, how do you want to proceed?', input),
+				message: __t('"%s" could not be resolved to a product, how do you want to proceed?', SanitizeHtml(input)),
 				title: __t('Create or assign product'),
 				onEscape: function()
 				{
```
