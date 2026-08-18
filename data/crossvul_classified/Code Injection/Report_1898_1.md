# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 1898_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1898_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-38 of the vulnerable file.

package io.onedev.server.model.support.inputspec.textinput;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.validation.ValidationException;

import com.google.common.collect.Lists;

import io.onedev.server.model.support.inputspec.InputSpec;
import io.onedev.server.model.support.inputspec.textinput.defaultvalueprovider.DefaultValueProvider;

public class TextInput {

	public static String getPropertyDef(InputSpec inputSpec, Map<String, Integer> indexes, 
			String pattern, DefaultValueProvider defaultValueProvider) {
		int index = indexes.get(inputSpec.getName());
		StringBuffer buffer = new StringBuffer();
		inputSpec.appendField(buffer, index, "String");
		inputSpec.appendCommonAnnotations(buffer, index);
		if (!inputSpec.isAllowEmpty())
			buffer.append("    @NotEmpty\n");
		if (pattern != null)
			buffer.append("    @Pattern(regexp=\"" + pattern + "\", message=\"Should match regular expression: " + pattern + "\")\n");
		inputSpec.appendMethods(buffer, index, "String", null, defaultValueProvider);
		
		return buffer.toString();
	}

	public static Object convertToObject(List<String> strings) {
		if (strings.size() == 0)
			return null;
		else if (strings.size() == 1)
			return strings.iterator().next();
		else
			throw new ValidationException("Not eligible for multi-value");
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
 
 	public static String getPropertyDef(InputSpec inputSpec, Map<String, Integer> indexes, 
 			String pattern, DefaultValueProvider defaultValueProvider) {
+		pattern = InputSpec.escape(pattern);
 		int index = indexes.get(inputSpec.getName());
 		StringBuffer buffer = new StringBuffer();
 		inputSpec.appendField(buffer, index, "String");
@@ -24,7 +25,7 @@
 		if (pattern != null)
 			buffer.append("    @Pattern(regexp=\"" + pattern + "\", message=\"Should match regular expression: " + pattern + "\")\n");
 		inputSpec.appendMethods(buffer, index, "String", null, defaultValueProvider);
-		
+
 		return buffer.toString();
 	}
 
```
