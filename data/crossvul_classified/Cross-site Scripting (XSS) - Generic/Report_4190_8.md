# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4190_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4190_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 21-61 of the vulnerable file.


$("#product-group-filter").on("change", function()
{
	var value = $("#product-group-filter option:selected").text();
	if (value === __t("All"))
	{
		value = "";
	}

	productsTable.column(7).search(value).draw();
});

if (typeof GetUriParam("product-group") !== "undefined")
{
	$("#product-group-filter").val(GetUriParam("product-group"));
	$("#product-group-filter").trigger("change");
}

$(document).on('click', '.product-delete-button', function(e)
{
	var objectName = $(e.currentTarget).attr('data-product-name');
	var objectId = $(e.currentTarget).attr('data-product-id');

	Grocy.Api.Get('stock/products/' + objectId,
		function(productDetails)
		{
			var stockAmount = productDetails.stock_amount || '0';

			if (stockAmount.toString() == "0")
			{
				bootbox.confirm({
					message: __t('Are you sure you want to deactivate this product "%s"?', objectName),
					closeButton: false,
					buttons: {
						confirm: {
							label: __t('Yes'),
							className: 'btn-success'
						},
						cancel: {
							label: __t('No'),
							className: 'btn-danger'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,7 +38,7 @@
 
 $(document).on('click', '.product-delete-button', function(e)
 {
-	var objectName = $(e.currentTarget).attr('data-product-name');
+	var objectName = SanitizeHtml($(e.currentTarget).attr('data-product-name'));
 	var objectId = $(e.currentTarget).attr('data-product-id');
 
 	Grocy.Api.Get('stock/products/' + objectId,
```
