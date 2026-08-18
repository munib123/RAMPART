# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 3053_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3053_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 119-159 of the vulnerable file.

import hudson.model.View;
import hudson.model.ViewGroupMixIn;
import hudson.model.WorkspaceCleanupThread;
import hudson.model.labels.LabelAtom;
import hudson.model.listeners.ItemListener;
import hudson.model.listeners.SCMListener;
import hudson.model.listeners.SaveableListener;
import hudson.remoting.Callable;
import hudson.remoting.LocalChannel;
import hudson.remoting.VirtualChannel;
import hudson.scm.RepositoryBrowser;
import hudson.scm.SCM;
import hudson.search.CollectionSearchIndex;
import hudson.search.SearchIndexBuilder;
import hudson.search.SearchItem;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.security.AuthorizationStrategy;
import hudson.security.BasicAuthenticationFilter;
import hudson.security.FederatedLoginService;
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import hudson.security.HudsonFilter;
import hudson.security.LegacyAuthorizationStrategy;
import hudson.security.LegacySecurityRealm;
import hudson.security.Permission;
import hudson.security.PermissionGroup;
import hudson.security.PermissionScope;
import hudson.security.SecurityMode;
import hudson.security.SecurityRealm;
import hudson.security.csrf.CrumbIssuer;
import hudson.slaves.Cloud;
import hudson.slaves.ComputerListener;
import hudson.slaves.DumbSlave;
import hudson.slaves.NodeDescriptor;
import hudson.slaves.NodeList;
import hudson.slaves.NodeProperty;
import hudson.slaves.NodePropertyDescriptor;
import hudson.slaves.NodeProvisioner;
import hudson.slaves.OfflineCause;
import hudson.slaves.RetentionStrategy;
import hudson.tasks.BuildWrapper;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,7 +136,6 @@
 import hudson.security.AuthorizationStrategy;
 import hudson.security.BasicAuthenticationFilter;
 import hudson.security.FederatedLoginService;
-import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
 import hudson.security.HudsonFilter;
 import hudson.security.LegacyAuthorizationStrategy;
 import hudson.security.LegacySecurityRealm;
@@ -1479,11 +1478,6 @@
      */
     @Exported(name="jobs")
     public List<TopLevelItem> getItems() {
-        if (authorizationStrategy instanceof AuthorizationStrategy.Unsecured ||
-            authorizationStrategy instanceof FullControlOnceLoggedInAuthorizationStrategy) {
-            return new ArrayList(items.values());
-        }
-
         List<TopLevelItem> viewableItems = new ArrayList<TopLevelItem>();
         for (TopLevelItem item : items.values()) {
             if (item.hasPermission(Item.READ))
```
