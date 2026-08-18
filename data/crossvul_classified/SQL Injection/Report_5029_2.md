# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in java
**Pair ID:** 5029_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5029_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```java
Lines 1-28 of the vulnerable file.

package com.dotmarketing.portlets.workflows.model;

import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

import com.dotmarketing.business.APILocator;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.util.UtilMethods;
import com.liferay.portal.model.User;

public class WorkflowSearcher {

	String schemeId;
	String assignedTo;
	String createdBy;
	String stepId;
	boolean open;
	boolean closed;
	boolean show4all;
	String keywords;
	String orderBy;
	int count = 20;
	int page = 0;
	User user;
	int totalCount;
	int daysOld=-1;
	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 import java.util.Map;
 
 import com.dotmarketing.business.APILocator;
+import com.dotmarketing.common.util.SQLUtil;
 import com.dotmarketing.exception.DotDataException;
 import com.dotmarketing.util.UtilMethods;
 import com.liferay.portal.model.User;
@@ -100,6 +101,9 @@
 		stepId = getStringValue("stepId", map);
 		keywords = getStringValue("keywords", map);
 		orderBy = getStringValue("orderBy", map);
+		
+		
+		orderBy= SQLUtil.sanitizeSortBy(orderBy);
 		show4all = getBooleanValue("show4all", map);
 		open = getBooleanValue("open", map);
 		closed = getBooleanValue("closed", map);
@@ -135,7 +139,7 @@
 	}
 
 	public String getOrderBy() {
-		return orderBy;
+		return SQLUtil.sanitizeSortBy(orderBy);
 	}
 
 	public List<WorkflowTask> findTasks() throws DotDataException {
@@ -154,6 +158,7 @@
 	}
 
 	public void setOrderBy(String orderBy) {
+		orderBy = SQLUtil.sanitizeSortBy(orderBy);
 		this.orderBy = orderBy;
 	}
 
```
