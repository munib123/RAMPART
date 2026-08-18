# CrossVul Fix Pair: Improper Privilege Management in java
**Pair ID:** 3047_2
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3047_2`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```java
Lines 35-75 of the vulnerable file.

import hudson.util.DescriptorList;
import hudson.util.EditDistance;
import hudson.util.XStream2;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.apache.commons.lang.StringUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Stack;
import java.util.StringTokenizer;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import jenkins.model.DirectlyModifiableTopLevelItemGroup;
import org.apache.commons.io.FileUtils;

/**
 * Convenience methods related to {@link Item}.
 * 
 * @author Kohsuke Kawaguchi
 */
public class Items {
    /**
     * List of all installed {@link TopLevelItem} types.
     *
     * @deprecated as of 1.286
     *      Use {@link #all()} for read access and {@link Extension} for registration.
     */
    @Deprecated
    public static final List<TopLevelItemDescriptor> LIST = (List)new DescriptorList<TopLevelItem>(TopLevelItem.class);

    /**
     * Used to behave differently when loading posted configuration as opposed to persisted configuration.
     * @see Trigger#start
     * @since 1.482
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,6 +52,8 @@
 import javax.annotation.Nonnull;
 
 import jenkins.model.DirectlyModifiableTopLevelItemGroup;
+import org.acegisecurity.context.SecurityContext;
+import org.acegisecurity.context.SecurityContextHolder;
 import org.apache.commons.io.FileUtils;
 
 /**
@@ -419,9 +421,7 @@
             throw new IllegalArgumentException();
         }
         String name = item.getName();
-        if (destination.getItem(name) != null) {
-            throw new IllegalArgumentException(name + " already exists");
-        }
+        verifyItemDoesNotAlreadyExist(destination, name, null);
         String oldFullName = item.getFullName();
         // TODO AbstractItem.renameTo has a more baroque implementation; factor it out into a utility method perhaps?
         File destDir = destination.getRootDirFor(item);
@@ -435,6 +435,33 @@
     }
 
     /**
+     * Securely check for the existence of an item before trying to create one with the same name.
+     * @param parent the folder where we are about to create/rename/move an item
+     * @param newName the proposed new name
+     * @param variant if not null, an existing item which we accept could be there
+     * @throws IllegalArgumentException if there is already something there, which you were supposed to know about
+     * @throws Failure if there is already something there but you should not be told details
+     */
+    static void verifyItemDoesNotAlreadyExist(@Nonnull ItemGroup<?> parent, @Nonnull String newName, @CheckForNull Item variant) throws IllegalArgumentException, Failure {
+        Item existing;
+        SecurityContext orig = ACL.impersonate(ACL.SYSTEM);
+        try {
+            existing = parent.getItem(newName);
+        } finally {
+            SecurityContextHolder.setContext(orig);
+        }
+        if (existing != null && existing != variant) {
+            if (existing.hasPermission(Item.DISCOVER)) {
+                String prefix = parent.getFullName();
+                throw new IllegalArgumentException((prefix.isEmpty() ? "" : prefix + "/") + newName + " already exists");
+            } else {
+                // Cannot hide its existence, so at least be as vague as possible.
+                throw new Failure("");
+            }
+        }
+    }
+
+    /**
      * Used to load/save job configuration.
      *
      * When you extend {@link Job} in a plugin, try to put the alias so
```
