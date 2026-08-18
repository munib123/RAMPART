# CrossVul Fix Pair: Improper Privilege Management in java
**Pair ID:** 3047_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3047_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```java
Lines 28-68 of the vulnerable file.

import hudson.AbortException;
import hudson.XmlFile;
import hudson.Util;
import hudson.Functions;
import hudson.BulkChange;
import hudson.cli.declarative.CLIMethod;
import hudson.cli.declarative.CLIResolver;
import hudson.model.listeners.ItemListener;
import hudson.model.listeners.SaveableListener;
import hudson.security.AccessControlled;
import hudson.security.Permission;
import hudson.security.ACL;
import hudson.util.AlternativeUiTextProvider;
import hudson.util.AlternativeUiTextProvider.Message;
import hudson.util.AtomicFileWriter;
import hudson.util.IOUtils;
import hudson.util.Secret;
import jenkins.model.DirectlyModifiableTopLevelItemGroup;
import jenkins.model.Jenkins;
import jenkins.security.NotReallyRoleSensitiveCallable;
import org.acegisecurity.Authentication;
import jenkins.util.xml.XMLUtils;

import org.apache.tools.ant.taskdefs.Copy;
import org.apache.tools.ant.types.FileSet;
import org.kohsuke.stapler.WebMethod;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.export.ExportedBean;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.List;
import java.util.ListIterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,7 +45,6 @@
 import jenkins.model.DirectlyModifiableTopLevelItemGroup;
 import jenkins.model.Jenkins;
 import jenkins.security.NotReallyRoleSensitiveCallable;
-import org.acegisecurity.Authentication;
 import jenkins.util.xml.XMLUtils;
 
 import org.apache.tools.ant.taskdefs.Copy;
@@ -76,7 +75,6 @@
 import org.xml.sax.SAXException;
 
 import javax.servlet.ServletException;
-import javax.servlet.ServletOutputStream;
 import javax.xml.transform.Source;
 import javax.xml.transform.TransformerException;
 import javax.xml.transform.stream.StreamResult;
@@ -236,27 +234,10 @@
                 if (this.name.equals(newName))
                     return;
 
-                // the test to see if the project already exists or not needs to be done in escalated privilege
-                // to avoid overwriting
-                ACL.impersonate(ACL.SYSTEM,new NotReallyRoleSensitiveCallable<Void,IOException>() {
-                    final Authentication user = Jenkins.getAuthentication();
-                    @Override
-                    public Void call() throws IOException {
-                        Item existing = parent.getItem(newName);
-                        if (existing != null && existing!=AbstractItem.this) {
-                            if (existing.getACL().hasPermission(user,Item.DISCOVER))
-                                // the look up is case insensitive, so we need "existing!=this"
-                                // to allow people to rename "Foo" to "foo", for example.
-                                // see http://www.nabble.com/error-on-renaming-project-tt18061629.html
-                                throw new IllegalArgumentException("Job " + newName + " already exists");
-                            else {
-                                // can't think of any real way to hide this, but at least the error message could be vague.
-                                throw new IOException("Unable to rename to " + newName);
-                            }
-                        }
-                        return null;
-                    }
-                });
+                // the lookup is case insensitive, so we should not fail if this item was the “existing” one
+                // to allow people to rename "Foo" to "foo", for example.
+                // see http://www.nabble.com/error-on-renaming-project-tt18061629.html
+                Items.verifyItemDoesNotAlreadyExist(parent, newName, this);
 
                 File oldRoot = this.getRootDir();
 
```
