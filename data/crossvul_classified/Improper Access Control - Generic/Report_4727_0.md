# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 4727_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4727_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 4-44 of the vulnerable file.

 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.deploy.hot;

import com.liferay.portal.kernel.deploy.hot.HotDeploy;
import com.liferay.portal.kernel.deploy.hot.HotDeployEvent;
import com.liferay.portal.kernel.deploy.hot.HotDeployException;
import com.liferay.portal.kernel.deploy.hot.HotDeployListener;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.servlet.ServletContextPool;
import com.liferay.portal.kernel.util.BasePortalLifecycle;
import com.liferay.portal.kernel.util.HttpUtil;
import com.liferay.portal.kernel.util.PortalLifecycle;
import com.liferay.portal.kernel.util.PortalLifecycleUtil;
import com.liferay.portal.kernel.util.PropertiesUtil;
import com.liferay.portal.kernel.util.StringBundler;
import com.liferay.portal.kernel.util.StringUtil;
import com.liferay.portal.security.pacl.PACLClassLoaderUtil;
import com.liferay.portal.security.pacl.PACLPolicy;
import com.liferay.portal.security.pacl.PACLPolicyManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.servlet.ServletContext;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
 import com.liferay.portal.kernel.log.Log;
 import com.liferay.portal.kernel.log.LogFactoryUtil;
 import com.liferay.portal.kernel.servlet.ServletContextPool;
+import com.liferay.portal.kernel.template.TemplateManagerUtil;
 import com.liferay.portal.kernel.util.BasePortalLifecycle;
 import com.liferay.portal.kernel.util.HttpUtil;
 import com.liferay.portal.kernel.util.PortalLifecycle;
@@ -105,7 +106,11 @@
 		_deployedServletContextNames.remove(
 			hotDeployEvent.getServletContextName());
 
-		PACLPolicyManager.unregister(hotDeployEvent.getContextClassLoader());
+		ClassLoader classLoader = hotDeployEvent.getContextClassLoader();
+
+		TemplateManagerUtil.destroy(classLoader);
+
+		PACLPolicyManager.unregister(classLoader);
 	}
 
 	public void registerListener(HotDeployListener hotDeployListener) {
```
