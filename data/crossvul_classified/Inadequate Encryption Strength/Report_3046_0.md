# CrossVul Fix Pair: Inadequate Encryption Strength in java
**Pair ID:** 3046_0
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3046_0`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```java
Lines 212-241 of the vulnerable file.

     *
     * Use {@link Items#getConfigFile(Item)}
     * or {@link AbstractItem#getConfigFile()} to obtain the file
     * to save the data.
     */
    void save() throws IOException;

    /**
     * Deletes this item.
     */
    void delete() throws IOException, InterruptedException;

    PermissionGroup PERMISSIONS = new PermissionGroup(Item.class,Messages._Item_Permissions_Title());
    Permission CREATE = new Permission(PERMISSIONS, "Create", Messages._Item_CREATE_description(), Permission.CREATE, PermissionScope.ITEM_GROUP);
    Permission DELETE = new Permission(PERMISSIONS, "Delete", Messages._Item_DELETE_description(), Permission.DELETE, PermissionScope.ITEM);
    Permission CONFIGURE = new Permission(PERMISSIONS, "Configure", Messages._Item_CONFIGURE_description(), Permission.CONFIGURE, PermissionScope.ITEM);
    Permission READ = new Permission(PERMISSIONS, "Read", Messages._Item_READ_description(), Permission.READ, PermissionScope.ITEM);
    Permission DISCOVER = new Permission(PERMISSIONS, "Discover", Messages._AbstractProject_DiscoverPermission_Description(), READ, PermissionScope.ITEM);
    /**
     * Ability to view configuration details.
     * If the user lacks {@link CONFIGURE} then any {@link Secret}s must be masked out, even in encrypted form.
     * @see Secret#ENCRYPTED_VALUE_PATTERN
     */
    Permission EXTENDED_READ = new Permission(PERMISSIONS,"ExtendedRead", Messages._AbstractProject_ExtendedReadPermission_Description(), CONFIGURE, Boolean.getBoolean("hudson.security.ExtendedReadPermission"), new PermissionScope[]{PermissionScope.ITEM});
    // TODO the following really belong in Job, not Item, but too late to move since the owner.name is encoded in the ID:
    Permission BUILD = new Permission(PERMISSIONS, "Build", Messages._AbstractProject_BuildPermission_Description(),  Permission.UPDATE, PermissionScope.ITEM);
    Permission WORKSPACE = new Permission(PERMISSIONS, "Workspace", Messages._AbstractProject_WorkspacePermission_Description(), Permission.READ, PermissionScope.ITEM);
    Permission WIPEOUT = new Permission(PERMISSIONS, "WipeOut", Messages._AbstractProject_WipeOutPermission_Description(), null, Functions.isWipeOutPermissionEnabled(), new PermissionScope[]{PermissionScope.ITEM});
    Permission CANCEL = new Permission(PERMISSIONS, "Cancel", Messages._AbstractProject_CancelPermission_Description(), BUILD, PermissionScope.ITEM);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -229,7 +229,7 @@
     Permission DISCOVER = new Permission(PERMISSIONS, "Discover", Messages._AbstractProject_DiscoverPermission_Description(), READ, PermissionScope.ITEM);
     /**
      * Ability to view configuration details.
-     * If the user lacks {@link CONFIGURE} then any {@link Secret}s must be masked out, even in encrypted form.
+     * If the user lacks {@link #CONFIGURE} then any {@link Secret}s must be masked out, even in encrypted form.
      * @see Secret#ENCRYPTED_VALUE_PATTERN
      */
     Permission EXTENDED_READ = new Permission(PERMISSIONS,"ExtendedRead", Messages._AbstractProject_ExtendedReadPermission_Description(), CONFIGURE, Boolean.getBoolean("hudson.security.ExtendedReadPermission"), new PermissionScope[]{PermissionScope.ITEM});
```
