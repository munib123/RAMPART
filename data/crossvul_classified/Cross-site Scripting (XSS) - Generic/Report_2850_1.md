# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2850_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2850_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 55-114 of the vulnerable file.

	$('#screenshot_box').css({'left': left + 'px'});
	$("#gray_out").fadeIn();
}

function submitPublish(id, type) {
	$("#PromptForm").submit();
}

function editTemplateElement(type, id) {
	simplePopup("/template_elements/edit/" + type + "/" + id);
}

function cancelPrompt(isolated) {
	if (isolated == undefined) {
		$("#gray_out").fadeOut();
	}
	$("#confirmation_box").fadeOut();
	$("#confirmation_box").empty();
}

function submitEventDeletion() {
	var formData = $('#PromptForm').serialize();
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		},
		data: formData,
		success:function (data, textStatus) {
			updateIndex(context_id, context);
			handleGenericAjaxResponse(data);
		},
		complete:function() {
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
		},
		type:"post",
		cache: false,
		url:"/" + type + "/" + action + "/" + id,
	});
}

function submitDeletion(context_id, action, type, id) {
	var context = 'event';
	if (type == 'template_elements') context = 'template';
	var formData = $('#PromptForm').serialize();
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		},
		data: formData,
		success:function (data, textStatus) {
			updateIndex(context_id, context);
			handleGenericAjaxResponse(data);
		},
		complete:function() {
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
		},
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,9 @@
 	$("#confirmation_box").empty();
 }
 
-function submitEventDeletion() {
+function submitDeletion(context_id, action, type, id) {
+	var context = 'event';
+	if (type == 'template_elements') context = 'template';
 	var formData = $('#PromptForm').serialize();
 	$.ajax({
 		beforeSend: function (XMLHttpRequest) {
@@ -94,31 +96,10 @@
 	});
 }
 
-function submitDeletion(context_id, action, type, id) {
-	var context = 'event';
-	if (type == 'template_elements') context = 'template';
-	var formData = $('#PromptForm').serialize();
-	$.ajax({
-		beforeSend: function (XMLHttpRequest) {
-			$(".loading").show();
-		},
-		data: formData,
-		success:function (data, textStatus) {
-			updateIndex(context_id, context);
-			handleGenericAjaxResponse(data);
-		},
-		complete:function() {
-			$(".loading").hide();
-			$("#confirmation_box").fadeOut();
-			$("#gray_out").fadeOut();
-		},
-		type:"post",
-		cache: false,
-		url:"/" + type + "/" + action + "/" + id,
-	});
-}
-
-function removeSighting(id, rawid, context) {
+function removeSighting(caller) {
+	var id = $(caller).data('id');
+	var rawid = $(caller).data('rawid');
+	var context = $(caller).data('context');
 	if (context != 'attribute') {
 		context = 'event';
 	}
@@ -130,15 +111,15 @@
 		data: formData,
 		success:function (data, textStatus) {
 			handleGenericAjaxResponse(data);
-		},
-		complete:function() {
-			$(".loading").hide();
-			$("#confirmation_box").fadeOut();
 			var org = "/" + $('#org_id').text();
 			updateIndex(id, 'event');
 			$.get( "/sightings/listSightings/" + rawid + "/" + context + org, function(data) {
 				$("#sightingsData").html(data);
 			});
+		},
+		complete:function() {
+			$(".loading").hide();
+			$("#confirmation_box").fadeOut();
 		},
 		type:"post",
 		cache: false,
```
