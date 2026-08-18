# CrossVul Fix Pair: Deserialization of Untrusted Data in javascript
**Pair ID:** 1893_4
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1893_4`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```javascript
Lines 1-37 of the vulnerable file.

onedev.server.markdown = {
	getCookiePrefix: function($container) {
		if ($container.hasClass("compact-mode"))
			return "markdownEditor.compactMode";
		else
			return "markdownEditor.normalMode";
	},
	fireInputEvent: function($input) {
		if(document.createEventObject) {
			$input[0].fireEvent("input");
		} else {
		    var evt = document.createEvent("HTMLEvents");
		    evt.initEvent("input", false, true);
		    $input[0].dispatchEvent(evt);
		}
	},
	onDomReady: function(containerId, callback, atWhoLimit, attachmentSupport, 
			attachmentMaxSize, canMentionUser, canReferenceEntity, 
			projectNamePattern, autosaveKey) {
		var $container = $("#" + containerId);
		$container.data("callback", callback);		
		$container.data("autosaveKey", autosaveKey);
		
		var $head = $container.children(".head");
		var $body = $container.children(".body");
		var $editLink = $head.find(".edit");
		var $previewLink = $head.find(".preview");
		var $splitLink = $head.find(".split");
		var $edit = $body.children(".edit");
		var $input = $edit.children("textarea");
		var $preview = $body.children(".preview");
		var $rendered = $preview.children(".markdown-rendered");
		var $help = $head.children(".help");

		$head.find(".dropdown>a").dropdown();
		
		$editLink.click(function() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
 		    $input[0].dispatchEvent(evt);
 		}
 	},
-	onDomReady: function(containerId, callback, atWhoLimit, attachmentSupport, 
+	onDomReady: function(containerId, callback, atWhoLimit, attachmentUploadUrl, 
 			attachmentMaxSize, canMentionUser, canReferenceEntity, 
 			projectNamePattern, autosaveKey) {
 		var $container = $("#" + containerId);
@@ -417,7 +417,7 @@
 		    });		
 	    }
 	    
-	    if (attachmentSupport) {
+	    if (attachmentUploadUrl) {
 	    	var inputEl = $input[0];
 	    	
 			inputEl.addEventListener("paste", function(e) {
@@ -482,20 +482,27 @@
 					}
 					
 					xhr.onload = function() {
+						var response = xhr.responseText;
+						var index = response.indexOf("<?xml");
+						if (index != -1)
+							response = response.substring(0, index);
 						if (xhr.status == 200) { 
-							callback("insertUrl", xhr.responseText, xhr.replaceMessage);
+							callback("insertUrl", response, xhr.replaceMessage);
 						} else { 
 							onedev.server.markdown.updateUploadMessage($input, 
-									"!!" + xhr.responseText + "!!", xhr.replaceMessage);
+									"!!" + response + "!!", xhr.replaceMessage);
 						}
 					};
 					xhr.onerror = function() {
 						onedev.server.markdown.updateUploadMessage($input, 
 								"!!Unable to connect to server!!", xhr.replaceMessage);
 					};
-					xhr.open("POST", "/attachment_upload", true);
+					
+					xhr.open("POST", attachmentUploadUrl, true);
 					xhr.setRequestHeader("File-Name", encodeURIComponent(file.name));
-					xhr.setRequestHeader("Attachment-Support", attachmentSupport);
+					xhr.setRequestHeader("Wicket-Ajax", "true");
+					xhr.setRequestHeader("Wicket-Ajax-BaseURL", Wicket.Ajax.baseUrl);
+					
 					xhr.send(file);
 				}
 			}
```
