# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 4727_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4727_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 11-52 of the vulnerable file.

 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.freemarker;

import com.liferay.portal.kernel.templateparser.TemplateContext;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.SetUtil;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.model.Theme;
import com.liferay.portal.template.TemplateContextHelper;
import com.liferay.portal.template.TemplatePortletPreferences;
import com.liferay.portal.theme.ThemeDisplay;
import com.liferay.portal.util.PropsValues;
import com.liferay.portal.util.WebKeys;

import freemarker.ext.beans.BeansWrapper;

import freemarker.template.utility.ObjectConstructor;

import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Mika Koivisto
 * @author Raymond Augé
 */
public class FreeMarkerTemplateContextHelper extends TemplateContextHelper {

	@Override
	public Map<String, Object> getHelperUtilities() {
		Map<String, Object> helperUtilities = super.getHelperUtilities();

		// Enum util

		helperUtilities.put(
			"enumUtil", BeansWrapper.getDefaultInstance().getEnumModels());

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,8 +28,6 @@
 
 import freemarker.ext.beans.BeansWrapper;
 
-import freemarker.template.utility.ObjectConstructor;
-
 import java.util.Map;
 import java.util.Set;
 
@@ -52,7 +50,7 @@
 
 		// Object util
 
-		helperUtilities.put("objectUtil", new ObjectConstructor());
+		helperUtilities.put("objectUtil", new LiferayObjectConstructor());
 
 		// Portlet preferences
 
```
