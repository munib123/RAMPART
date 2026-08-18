# CrossVul Fix Pair: Improper Privilege Management in java
**Pair ID:** 3047_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3047_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```java
Lines 245-288 of the vulnerable file.

        // reload from the new config
        final File rootDir = result.getRootDir();
        result = Items.whileUpdatingByXml(new NotReallyRoleSensitiveCallable<T,IOException>() {
            @Override public T call() throws IOException {
                return (T) Items.load(parent, rootDir);
            }
        });
        result.onCopiedFrom(src);

        add(result);
        ItemListener.fireOnCopied(src,result);
        Jenkins.getInstance().rebuildDependencyGraphAsync();

        return result;
    }

    public synchronized TopLevelItem createProjectFromXML(String name, InputStream xml) throws IOException {
        acl.checkPermission(Item.CREATE);

        Jenkins.getInstance().getProjectNamingStrategy().checkName(name);
        if (parent.getItem(name) != null) {
            throw new IllegalArgumentException(parent.getDisplayName() + " already contains an item '" + name + "'");
        }
        // TODO what if we have no DISCOVER permission on the existing job?

        // place it as config.xml
        File configXml = Items.getConfigFile(getRootDirFor(name)).getFile();
        final File dir = configXml.getParentFile();
        dir.mkdirs();
        boolean success = false;
        try {
            XMLUtils.safeTransform((Source)new StreamSource(xml), new StreamResult(configXml));

            // load it
            TopLevelItem result = Items.whileUpdatingByXml(new NotReallyRoleSensitiveCallable<TopLevelItem,IOException>() {
                @Override public TopLevelItem call() throws IOException {
                    return (TopLevelItem) Items.load(parent, dir);
                }
            });

            success = acl.getACL().hasCreatePermission(Jenkins.getAuthentication(), parent, result.getDescriptor())
                && result.getDescriptor().isApplicableIn(parent);

            add(result);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -262,10 +262,7 @@
         acl.checkPermission(Item.CREATE);
 
         Jenkins.getInstance().getProjectNamingStrategy().checkName(name);
-        if (parent.getItem(name) != null) {
-            throw new IllegalArgumentException(parent.getDisplayName() + " already contains an item '" + name + "'");
-        }
-        // TODO what if we have no DISCOVER permission on the existing job?
+        Items.verifyItemDoesNotAlreadyExist(parent, name, null);
 
         // place it as config.xml
         File configXml = Items.getConfigFile(getRootDirFor(name)).getFile();
@@ -318,9 +315,7 @@
         acl.getACL().checkCreatePermission(parent, type);
 
         Jenkins.getInstance().getProjectNamingStrategy().checkName(name);
-        if(parent.getItem(name)!=null)
-            throw new IllegalArgumentException("Project of the name "+name+" already exists");
-        // TODO problem with DISCOVER as noted above
+        Items.verifyItemDoesNotAlreadyExist(parent, name, null);
 
         TopLevelItem item = type.newInstance(parent, name);
         try {
```
