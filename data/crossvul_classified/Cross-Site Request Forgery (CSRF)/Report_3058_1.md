# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 3058_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3058_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 2468-2508 of the vulnerable file.

                    return null;
            }

            if(!(item instanceof ItemGroup))
                return null;    // this item can't have any children

            if (!item.hasPermission(Item.READ))
                return null; // TODO consider DISCOVER

            parent = (ItemGroup) item;
        }
    }

    public @CheckForNull Item getItemByFullName(String fullName) {
        return getItemByFullName(fullName,Item.class);
    }

    /**
     * Gets the user of the given name.
     *
     * @return the user of the given name (which may or may not be an id), if that person exists or the invoker {@link #hasPermission} on {@link #ADMINISTER}; else null
     * @see User#get(String,boolean), {@link User#getById(String, boolean)}
     */
    public @CheckForNull User getUser(String name) {
        return User.get(name,hasPermission(ADMINISTER));
    }

    public synchronized TopLevelItem createProject( TopLevelItemDescriptor type, String name ) throws IOException {
        return createProject(type, name, true);
    }

    public synchronized TopLevelItem createProject( TopLevelItemDescriptor type, String name, boolean notify ) throws IOException {
        return itemGroupMixIn.createProject(type,name,notify);
    }

    /**
     * Overwrites the existing item by new one.
     *
     * <p>
     * This is a short cut for deleting an existing job and adding a new one.
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2485,11 +2485,11 @@
     /**
      * Gets the user of the given name.
      *
-     * @return the user of the given name (which may or may not be an id), if that person exists or the invoker {@link #hasPermission} on {@link #ADMINISTER}; else null
+     * @return the user of the given name (which may or may not be an id), if that person exists; else null
      * @see User#get(String,boolean), {@link User#getById(String, boolean)}
      */
     public @CheckForNull User getUser(String name) {
-        return User.get(name,hasPermission(ADMINISTER));
+        return User.get(name, User.ALLOW_USER_CREATION_VIA_URL && hasPermission(ADMINISTER));
     }
 
     public synchronized TopLevelItem createProject( TopLevelItemDescriptor type, String name ) throws IOException {
```
