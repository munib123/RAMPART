# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 1893_3
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1893_3`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 1-25 of the vulnerable file.

package io.onedev.server.web.component.markdown;

import static org.apache.wicket.ajax.attributes.CallbackParameter.explicit;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;
import javax.servlet.http.Cookie;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.wicket.AttributeModifier;
import org.apache.wicket.Component;
import org.apache.wicket.ajax.AjaxChannel;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.ajax.attributes.AjaxRequestAttributes;
import org.apache.wicket.behavior.AttributeAppender;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,9 +2,11 @@
 
 import static org.apache.wicket.ajax.attributes.CallbackParameter.explicit;
 
+import java.io.IOException;
 import java.io.Serializable;
 import java.io.UnsupportedEncodingException;
 import java.net.URLDecoder;
+import java.net.URLEncoder;
 import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
 import java.util.HashMap;
@@ -13,8 +15,9 @@
 
 import javax.annotation.Nullable;
 import javax.servlet.http.Cookie;
-
-import org.apache.commons.lang3.SerializationUtils;
+import javax.servlet.http.HttpServletRequest;
+import javax.servlet.http.HttpServletResponse;
+
 import org.apache.commons.lang3.StringUtils;
 import org.apache.commons.text.StringEscapeUtils;
 import org.apache.wicket.AttributeModifier;
@@ -41,7 +44,8 @@
 import org.apache.wicket.request.http.WebRequest;
 import org.apache.wicket.request.mapper.parameter.PageParameters;
 import org.apache.wicket.request.resource.PackageResourceReference;
-import org.apache.wicket.util.crypt.Base64;
+import org.slf4j.Logger;
+import org.slf4j.LoggerFactory;
 import org.unbescape.javascript.JavaScriptEscape;
 
 import com.fasterxml.jackson.core.JsonProcessingException;
@@ -72,6 +76,8 @@
 
 	protected static final int ATWHO_LIMIT = 10;
 	
+	private static final Logger logger = LoggerFactory.getLogger(MarkdownEditor.class);
+	
 	private final boolean compactMode;
 	
 	private final boolean initialSplit;
@@ -82,7 +88,9 @@
 	
 	private TextArea<String> input;
 
-	private AbstractPostAjaxBehavior ajaxBehavior;
+	private AbstractPostAjaxBehavior actionBehavior;
+	
+	private AbstractPostAjaxBehavior attachmentUploadBehavior;
 	
 	/**
 	 * @param id 
@@ -251,7 +259,7 @@
 		
 		container.add(new WebMarkupContainer("canAttachFile").setVisible(getAttachmentSupport()!=null));
 		
-		container.add(ajaxBehavior = new AbstractPostAjaxBehavior() {
+		container.add(actionBehavior = new AbstractPostAjaxBehavior() {
 
 			@Override
 			protected void updateAjaxAttributes(AjaxRequestAttributes attributes) {
@@ -452,6 +460,7 @@
 					String replaceMessage = params.getParameterValue("param2").toString();
 					String url = getAttachmentSupport().getAttachmentUrl(name);
 					insertUrl(target, isWebSafeImage(name), url, name, replaceMessage);
+					
 					break;
 				default:
 					throw new IllegalStateException("Unknown action: " + action);
@@ -459,6 +468,34 @@
 			}
 			
 		});
+		
+		container.add(attachmentUploadBehavior = new AbstractPostAjaxBehavior() {
+			
+			@Override
+			protected void respond(AjaxRequestTarget target) {
+				Preconditions.checkNotNull(getAttachmentSupport(), "Unexpected attachment upload request");
+				HttpServletRequest request = (HttpServletRequest) RequestCycle.get().getRequest().getContainerRequest();
+				HttpServletResponse response = (HttpServletResponse) RequestCycle.get().getResponse().getContainerResponse();
+				try {
+					String fileName = URLDecoder.decode(request.getHeader("File-Name"), StandardCharsets.UTF_8.name());
+					String attachmentName = getAttachmentSupport().saveAttachment(fileName, request.getInputStream());
+					response.getWriter().print(URLEncoder.encode(attachmentName, StandardCharsets.UTF_8.name()));
+					response.setStatus(HttpServletResponse.SC_OK);
+				} catch (Exception e) {
+					logger.error("Error uploading attachment.", e);
+					try {
+						if (e.getMessage() != null)
+							response.getWriter().print(e.getMessage());
+						else
+							response.getWriter().print("Internal server error");
+					} catch (IOException e2) {
+						throw new RuntimeException(e2);
+					}
+					response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
+				}
+			}
+			
+		});
 	}
 	
 	@Override
@@ -476,18 +513,9 @@
 		super.renderHead(response);
 		response.render(JavaScriptHeaderItem.forReference(new MarkdownResourceReference()));
 		
-		String encodedAttachmentSupport;
-		if (getAttachmentSupport() != null) {
-			encodedAttachmentSupport = Base64.encodeBase64String(SerializationUtils.serialize(getAttachmentSupport()));
-			encodedAttachmentSupport = StringUtils.deleteWhitespace(encodedAttachmentSupport);
-			encodedAttachmentSupport = StringEscapeUtils.escapeEcmaScript(encodedAttachmentSupport);
-			encodedAttachmentSupport = "'" + encodedAttachmentSupport + "'";
-		} else {
-			encodedAttachmentSupport = "undefined";
-		}
-		
-		String callback = ajaxBehavior.getCallbackFunction(explicit("action"), explicit("param1"), explicit("param2"), 
+		String actionCallback = actionBehavior.getCallbackFunction(explicit("action"), explicit("param1"), explicit("param2"), 
 				explicit("param3")).toString();
+		String attachmentUploadUrl = attachmentUploadBehavior.getCallbackUrl().toString();
 		
 		String autosaveKey = getAutosaveKey();
 		if (autosaveKey != null)
@@ -497,10 +525,10 @@
 		
 		String script = String.format("onedev.server.markdown.onDomReady('%s', %s, %d, %s, %d, %b, %b, '%s', %s);", 
 				container.getMarkupId(), 
-				callback, 
+				actionCallback, 
 				ATWHO_LIMIT, 
-				encodedAttachmentSupport, 
-				getAttachmentSupport()!=null?getAttachmentSupport().getAttachmentMaxSize():0,
+				getAttachmentSupport()!=null? "'" + attachmentUploadUrl + "'": "undefined", 
+				getAttachmentSupport()!=null? getAttachmentSupport().getAttachmentMaxSize(): 0,
 				getUserMentionSupport() != null,
 				getReferenceSupport() != null, 
 				JavaScriptEscape.escapeJavaScript(ProjectNameValidator.PATTERN.pattern()),
```
