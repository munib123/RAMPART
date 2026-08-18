# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 2083_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2083_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 1-22 of the vulnerable file.

/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.web.servlet.tags.form;

import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
- * Copyright 2002-2013 the original author or authors.
+ * Copyright 2002-2014 the original author or authors.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -16,6 +16,7 @@
 
 package org.springframework.web.servlet.tags.form;
 
+import java.io.UnsupportedEncodingException;
 import java.util.Map;
 
 import javax.servlet.ServletRequest;
@@ -32,6 +33,7 @@
 import org.springframework.util.StringUtils;
 import org.springframework.web.servlet.support.RequestDataValueProcessor;
 import org.springframework.web.util.HtmlUtils;
+import org.springframework.web.util.UriUtils;
 
 /**
  * Databinding-aware JSP tag for rendering an HTML '{@code form}' whose
@@ -442,6 +444,13 @@
 		}
 		else {
 			String requestUri = getRequestContext().getRequestUri();
+			String encoding = pageContext.getResponse().getCharacterEncoding();
+			try {
+				requestUri = UriUtils.encodePath(requestUri, encoding);
+			}
+			catch (UnsupportedEncodingException e) {
+				throw new JspException(e);
+			}
 			ServletResponse response = this.pageContext.getResponse();
 			if (response instanceof HttpServletResponse) {
 				requestUri = ((HttpServletResponse) response).encodeURL(requestUri);
```
