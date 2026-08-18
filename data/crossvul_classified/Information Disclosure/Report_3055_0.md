# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 3055_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3055_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 1870-1910 of the vulnerable file.

    public SearchIndexBuilder makeSearchIndex() {
        return super.makeSearchIndex()
            .add("configure", "config","configure")
            .add("manage")
            .add("log")
            .add(new CollectionSearchIndex<TopLevelItem>() {
                protected SearchItem get(String key) { return getItemByFullName(key, TopLevelItem.class); }
                protected Collection<TopLevelItem> all() { return getAllItems(TopLevelItem.class); }
            })
            .add(getPrimaryView().makeSearchIndex())
            .add(new CollectionSearchIndex() {// for computers
                protected Computer get(String key) { return getComputer(key); }
                protected Collection<Computer> all() { return computers.values(); }
            })
            .add(new CollectionSearchIndex() {// for users
                protected User get(String key) { return User.get(key,false); }
                protected Collection<User> all() { return User.getAll(); }
            })
            .add(new CollectionSearchIndex() {// for views
                protected View get(String key) { return getView(key); }
                protected Collection<View> all() { return views; }
            });
    }

    public String getUrlChildPrefix() {
        return "job";
    }

    /**
     * Gets the absolute URL of Jenkins, such as {@code http://localhost/jenkins/}.
     *
     * <p>
     * This method first tries to use the manually configured value, then
     * fall back to {@link #getRootUrlFromRequest}.
     * It is done in this order so that it can work correctly even in the face
     * of a reverse proxy.
     *
     * @return null if this parameter is not configured by the user and the calling thread is not in an HTTP request; otherwise the returned URL will always have the trailing {@code /}
     * @since 1.66
     * @see <a href="https://wiki.jenkins-ci.org/display/JENKINS/Hyperlinks+in+HTML">Hyperlinks in HTML</a>
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1887,7 +1887,7 @@
             })
             .add(new CollectionSearchIndex() {// for views
                 protected View get(String key) { return getView(key); }
-                protected Collection<View> all() { return views; }
+                protected Collection<View> all() { return viewGroupMixIn.getViews(); }
             });
     }
 
```
