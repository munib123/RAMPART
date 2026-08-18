# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 4549_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4549_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-22 of the vulnerable file.

/*
 * Copyright 2017 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.database;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.InitialDirContext;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
- * Copyright 2017 Anton Tananaev (anton@traccar.org)
+ * Copyright 2017 - 2020 Anton Tananaev (anton@traccar.org)
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -81,7 +81,7 @@
         if (this.adminFilter != null) {
             try {
                 InitialDirContext context = initContext();
-                String searchString = adminFilter.replace(":login", accountName);
+                String searchString = adminFilter.replace(":login", encodeForLdap(accountName));
                 SearchControls searchControls = new SearchControls();
                 searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                 NamingEnumeration<SearchResult> results = context.search(searchBase, searchString, searchControls);
@@ -107,7 +107,7 @@
     private SearchResult lookupUser(String accountName) throws NamingException {
         InitialDirContext context = initContext();
 
-        String searchString = searchFilter.replace(":login", accountName);
+        String searchString = searchFilter.replace(":login", encodeForLdap(accountName));
 
         SearchControls searchControls = new SearchControls();
         String[] attributeFilter = {idAttribute, nameAttribute, mailAttribute};
@@ -176,4 +176,34 @@
         return false;
     }
 
+    public String encodeForLdap(String input) {
+        if( input == null ) {
+            return null;
+        }
+        StringBuilder sb = new StringBuilder();
+        for (int i = 0; i < input.length(); i++) {
+            char c = input.charAt(i);
+            switch (c) {
+                case '\\':
+                    sb.append("\\5c");
+                    break;
+                case '*':
+                    sb.append("\\2a");
+                    break;
+                case '(':
+                    sb.append("\\28");
+                    break;
+                case ')':
+                    sb.append("\\29");
+                    break;
+                case '\0':
+                    sb.append("\\00");
+                    break;
+                default:
+                    sb.append(c);
+            }
+        }
+        return sb.toString();
+    }
+
 }
```
