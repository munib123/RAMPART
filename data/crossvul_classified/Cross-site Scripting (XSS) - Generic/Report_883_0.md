# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 883_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `883_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 15-55 of the vulnerable file.

import ca.uhn.fhir.rest.client.impl.GenericClient;
import ca.uhn.fhir.to.model.HomeRequest;
import ca.uhn.fhir.util.ExtensionConstants;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicHeader;
import org.hl7.fhir.dstu3.model.CapabilityStatement;
import org.hl7.fhir.dstu3.model.CapabilityStatement.CapabilityStatementRestComponent;
import org.hl7.fhir.dstu3.model.CapabilityStatement.CapabilityStatementRestResourceComponent;
import org.hl7.fhir.dstu3.model.DecimalType;
import org.hl7.fhir.dstu3.model.Extension;
import org.hl7.fhir.instance.model.api.IAnyResource;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.instance.model.api.IDomainResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.ModelMap;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.TemplateEngine;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.*;

import static org.apache.commons.lang3.StringUtils.defaultString;

public class BaseController {
	static final String PARAM_RESOURCE = "resource";
	static final String RESOURCE_COUNT_EXT_URL = "http://hl7api.sourceforge.net/hapi-fhir/res/extdefs.html#resourceCount";
	private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory.getLogger(BaseController.class);
	@Autowired
	protected TesterConfig myConfig;
	private Map<FhirVersionEnum, FhirContext> myContexts = new HashMap<FhirVersionEnum, FhirContext>();
	private List<String> myFilterHeaders;
	@Autowired
	private ITemplateEngine myTemplateEngine;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,6 @@
 import org.springframework.beans.factory.annotation.Autowired;
 import org.springframework.ui.ModelMap;
 import org.thymeleaf.ITemplateEngine;
-import org.thymeleaf.TemplateEngine;
 
 import javax.servlet.ServletException;
 import javax.servlet.http.HttpServletRequest;
@@ -63,14 +62,14 @@
 		final String serverBase = theRequest.getServerBase(theServletRequest, myConfig);
 		final String serverName = theRequest.getServerName(myConfig);
 		final String apiKey = theRequest.getApiKey(theServletRequest, myConfig);
-		theModel.put("serverId", serverId);
-		theModel.put("base", serverBase);
-		theModel.put("baseName", serverName);
-		theModel.put("apiKey", apiKey);
-		theModel.put("resourceName", defaultString(theRequest.getResource()));
-		theModel.put("encoding", theRequest.getEncoding());
-		theModel.put("pretty", theRequest.getPretty());
-		theModel.put("_summary", theRequest.get_summary());
+		theModel.put("serverId", sanitizeInput(serverId));
+		theModel.put("base", sanitizeInput(serverBase));
+		theModel.put("baseName", sanitizeInput(serverName));
+		theModel.put("apiKey", sanitizeInput(apiKey));
+		theModel.put("resourceName", sanitizeInput(defaultString(theRequest.getResource())));
+		theModel.put("encoding", sanitizeInput(theRequest.getEncoding()));
+		theModel.put("pretty", sanitizeInput(theRequest.getPretty()));
+		theModel.put("_summary", sanitizeInput(theRequest.get_summary()));
 		theModel.put("serverEntries", myConfig.getIdToServerName());
 
 		return loadAndAddConf(theServletRequest, theRequest, theModel);
@@ -307,7 +306,6 @@
 		throw new IllegalStateException("Unknown version: " + theRequest.getFhirVersion(myConfig));
 	}
 
-
 	private IResource loadAndAddConfDstu2(HttpServletRequest theServletRequest, final HomeRequest theRequest, final ModelMap theModel) {
 		CaptureInterceptor interceptor = new CaptureInterceptor();
 		GenericClient client = theRequest.newClient(theServletRequest, getContext(theRequest), myConfig, interceptor);
@@ -746,4 +744,21 @@
 
 	}
 
+	private static String sanitizeInput(String theString) {
+		String retVal = theString;
+		if (retVal != null) {
+			for (int i = 0; i < retVal.length(); i++) {
+				char nextChar = retVal.charAt(i);
+				switch (nextChar) {
+					case '\'':
+					case '"':
+					case '<':
+					case '>':
+						retVal = retVal.replace(nextChar, '_');
+				}
+			}
+		}
+		return retVal;
+	}
+
 }
```
