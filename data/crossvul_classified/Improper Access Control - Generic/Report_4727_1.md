# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 4727_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4727_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 5-45 of the vulnerable file.

 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.freemarker;

import com.liferay.portal.kernel.cache.PortalCache;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.template.Template;
import com.liferay.portal.kernel.template.TemplateContextType;
import com.liferay.portal.kernel.template.TemplateException;
import com.liferay.portal.kernel.template.TemplateManager;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.template.RestrictedTemplate;
import com.liferay.portal.template.TemplateContextHelper;
import com.liferay.portal.util.PropsValues;

import freemarker.cache.ClassTemplateLoader;
import freemarker.cache.MultiTemplateLoader;
import freemarker.cache.TemplateLoader;

import freemarker.template.Configuration;

import java.io.IOException;

import java.util.Map;

/**
 * @author Mika Koivisto
 * @author Tina Tina
 */
public class FreeMarkerManager implements TemplateManager {

	public void clearCache() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,10 @@
 import com.liferay.portal.kernel.template.TemplateException;
 import com.liferay.portal.kernel.template.TemplateManager;
 import com.liferay.portal.kernel.util.StringPool;
+import com.liferay.portal.security.lang.PortalSecurityManagerThreadLocal;
+import com.liferay.portal.security.pacl.PACLClassLoaderUtil;
+import com.liferay.portal.security.pacl.PACLPolicy;
+import com.liferay.portal.security.pacl.PACLPolicyManager;
 import com.liferay.portal.template.RestrictedTemplate;
 import com.liferay.portal.template.TemplateContextHelper;
 import com.liferay.portal.util.PropsValues;
@@ -35,6 +39,7 @@
 import java.io.IOException;
 
 import java.util.Map;
+import java.util.concurrent.ConcurrentHashMap;
 
 /**
  * @author Mika Koivisto
@@ -63,6 +68,10 @@
 			return;
 		}
 
+		_classLoaderHelperUtilities.clear();
+
+		_classLoaderHelperUtilities = null;
+
 		_configuration.clearEncodingMap();
 		_configuration.clearSharedVariables();
 		_configuration.clearTemplateCache();
@@ -84,11 +93,55 @@
 		_templateContextHelper = null;
 	}
 
+	public void destroy(ClassLoader classLoader) {
+		_classLoaderHelperUtilities.remove(classLoader);
+	}
+
 	public Template getTemplate(
 		String templateId, String templateContent, String errorTemplateId,
 		String errorTemplateContent, TemplateContextType templateContextType) {
 
-		if (templateContextType.equals(TemplateContextType.EMPTY)) {
+		if (templateContextType.equals(TemplateContextType.CLASS_LOADER)) {
+
+			// This template will have all of its utilities initialized within
+			// the class loader of the current thread
+
+			ClassLoader contextClassLoader =
+				PACLClassLoaderUtil.getContextClassLoader();
+
+			PACLPolicy threadLocalPACLPolicy =
+				PortalSecurityManagerThreadLocal.getPACLPolicy();
+
+			PACLPolicy contextClassLoaderPACLPolicy =
+				PACLPolicyManager.getPACLPolicy(contextClassLoader);
+
+			try {
+				PortalSecurityManagerThreadLocal.setPACLPolicy(
+					contextClassLoaderPACLPolicy);
+
+				Map<String, Object> helperUtilities =
+					_classLoaderHelperUtilities.get(contextClassLoader);
+
+				if (helperUtilities == null) {
+					helperUtilities =
+						_templateContextHelper.getHelperUtilities();
+
+					_classLoaderHelperUtilities.put(
+						contextClassLoader, helperUtilities);
+				}
+
+				return new PACLFreeMarkerTemplate(
+					templateId, templateContent, errorTemplateId,
+					errorTemplateContent, helperUtilities, _configuration,
+					_templateContextHelper, _stringTemplateLoader,
+					contextClassLoaderPACLPolicy);
+			}
+			finally {
+				PortalSecurityManagerThreadLocal.setPACLPolicy(
+					threadLocalPACLPolicy);
+			}
+		}
+		else if (templateContextType.equals(TemplateContextType.EMPTY)) {
 			return new FreeMarkerTemplate(
 					templateId, templateContent, errorTemplateId,
 					errorTemplateContent, null, _configuration,
@@ -186,6 +239,8 @@
 		_configuration.setDefaultEncoding(StringPool.UTF8);
 		_configuration.setLocalizedLookup(
 			PropsValues.FREEMARKER_ENGINE_LOCALIZED_LOOKUP);
+		_configuration.setNewBuiltinClassResolver(
+			new LiferayTemplateClassResolver());
 		_configuration.setObjectWrapper(new LiferayObjectWrapper());
 		_configuration.setTemplateLoader(multiTemplateLoader);
 		_configuration.setTemplateUpdateDelay(
@@ -217,6 +272,8 @@
 
 	private static Log _log = LogFactoryUtil.getLog(FreeMarkerManager.class);
 
+	private Map<ClassLoader, Map<String, Object>> _classLoaderHelperUtilities =
+		new ConcurrentHashMap<ClassLoader, Map<String, Object>>();
 	private Configuration _configuration;
 	private Map<String, Object> _restrictedHelperUtilities;
 	private Map<String, Object> _standardHelperUtilities;
```
