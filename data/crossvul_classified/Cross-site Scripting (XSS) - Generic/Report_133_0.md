# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 133_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `133_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 3143-3183 of the vulnerable file.

			$(".loading").show();
		},
		data: formData,
		success:function (data, textStatus) {
			$('#gitResult').text(data);
			$('#gitResult').removeClass('hidden');
		},
		complete:function() {
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
		},
		type:"post",
		cache: false,
		url:"/servers/update",
	});
}

$(".cortex-json").click(function() {
	var cortex_data = $(this).data('cortex-json');
	cortex_data = JSON.stringify(cortex_data, null, 2);
	var popupHtml = '<pre class="simplepre">' + cortex_data + '</pre>';
	popupHtml += '<div class="close-icon useCursorPointer" onClick="closeScreenshot();"></div>';
	$('#screenshot_box').html(popupHtml);
	$('#screenshot_box').show();
	$('#screenshot_box').css({'padding': '5px'});
	left = ($(window).width() / 2) - ($('#screenshot_box').width() / 2);
	if (($('#screenshot_box').height() + 250) > $(window).height()) {
		$('#screenshot_box').height($(window).height() - 250);
		$('#screenshot_box').css("overflow-y", "scroll");
		$('#screenshot_box').css("overflow-x", "hidden");
	}
	$('#screenshot_box').css({'left': left + 'px'});
	$("#gray_out").fadeIn();
});

// Show $(id) if the enable parameter evaluates to true. Hide it otherwise
function checkAndEnable(id, enable) {
	if (enable) {
		$(id).show();
	} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3160,7 +3160,7 @@
 
 $(".cortex-json").click(function() {
 	var cortex_data = $(this).data('cortex-json');
-	cortex_data = JSON.stringify(cortex_data, null, 2);
+	cortex_data = htmlEncode(JSON.stringify(cortex_data, null, 2));
 	var popupHtml = '<pre class="simplepre">' + cortex_data + '</pre>';
 	popupHtml += '<div class="close-icon useCursorPointer" onClick="closeScreenshot();"></div>';
 	$('#screenshot_box').html(popupHtml);
```
