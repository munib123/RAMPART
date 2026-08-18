# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3079_5
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3079_5`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 13-53 of the vulnerable file.


package com.vmware.xenon.common.test;

import static org.junit.Assert.assertTrue;

import static com.vmware.xenon.services.common.authn.BasicAuthenticationUtils.constructBasicAuth;

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.vmware.xenon.common.Operation;
import com.vmware.xenon.common.Service.Action;
import com.vmware.xenon.common.ServiceDocument;
import com.vmware.xenon.common.ServiceHost;
import com.vmware.xenon.common.UriUtils;
import com.vmware.xenon.common.Utils;
import com.vmware.xenon.services.common.ExampleService.ExampleServiceState;
import com.vmware.xenon.services.common.QueryTask;
import com.vmware.xenon.services.common.QueryTask.Query;
import com.vmware.xenon.services.common.QueryTask.Query.Builder;
import com.vmware.xenon.services.common.QueryTask.QuerySpecification;
import com.vmware.xenon.services.common.ResourceGroupService.ResourceGroupState;
import com.vmware.xenon.services.common.RoleService.Policy;
import com.vmware.xenon.services.common.RoleService.RoleState;
import com.vmware.xenon.services.common.ServiceUriPaths;
import com.vmware.xenon.services.common.UserGroupService;
import com.vmware.xenon.services.common.UserGroupService.UserGroupState;
import com.vmware.xenon.services.common.UserService.UserState;
import com.vmware.xenon.services.common.authn.AuthenticationRequest;
import com.vmware.xenon.services.common.authn.BasicAuthenticationService;

/**
 * Consider using {@link com.vmware.xenon.common.AuthorizationSetupHelper}
 */
public class AuthorizationHelper {

    private String userGroupLink;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,7 @@
 import com.vmware.xenon.common.ServiceHost;
 import com.vmware.xenon.common.UriUtils;
 import com.vmware.xenon.common.Utils;
+import com.vmware.xenon.services.common.ExampleService;
 import com.vmware.xenon.services.common.ExampleService.ExampleServiceState;
 import com.vmware.xenon.services.common.QueryTask;
 import com.vmware.xenon.services.common.QueryTask.Query;
@@ -269,6 +270,22 @@
                                 UriUtils.buildUriPath(ServiceUriPaths.CORE_AUTHZ_USERS, email))
                         .build());
 
+        // Create resource group to allow access on utility paths
+        String statsResourceGroupLink = createResourceGroup(target, "stats-resource-group",
+                Builder.create()
+                        .addFieldClause(
+                                ServiceDocument.FIELD_NAME_SELF_LINK,
+                                ExampleService.FACTORY_LINK + ServiceHost.SERVICE_URI_SUFFIX_STATS)
+                        .build());
+
+        String subscriptionsResourceGroupLink = createResourceGroup(target, "subs-resource-group",
+                Builder.create()
+                        .addFieldClause(
+                                ServiceDocument.FIELD_NAME_SELF_LINK,
+                                ServiceUriPaths.CORE_LOCAL_QUERY_TASKS
+                                        + ServiceHost.SERVICE_URI_SUFFIX_SUBSCRIPTIONS)
+                        .build());
+
         Collection<String> paths = new HashSet<>();
 
         // Create roles tying these together
@@ -283,6 +300,16 @@
         // Create role authorizing access to the user's own query tasks
         paths.add(createRole(target, userGroupLink, queryTaskResourceGroupLink,
                 new HashSet<>(Arrays.asList(Action.GET, Action.POST, Action.PATCH, Action.DELETE))));
+
+        // Create role authorizing access to /stats
+        paths.add(createRole(target, userGroupLink, statsResourceGroupLink,
+                new HashSet<>(
+                        Arrays.asList(Action.GET, Action.POST, Action.PATCH, Action.DELETE))));
+
+        // Create role authorizing access to /subscriptions of query tasks
+        paths.add(createRole(target, userGroupLink, subscriptionsResourceGroupLink,
+                new HashSet<>(
+                        Arrays.asList(Action.GET, Action.POST, Action.PATCH, Action.DELETE))));
         return paths;
     }
 
```
