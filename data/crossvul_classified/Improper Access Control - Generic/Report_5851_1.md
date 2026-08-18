# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 5851_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5851_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 919-959 of the vulnerable file.

     * @return
     *      Can be empty but never null.
     */
    public static <T extends Describable<T>>
    List<T> newInstancesFromHeteroList(StaplerRequest req, JSONObject formData, String key,
                Collection<? extends Descriptor<T>> descriptors) throws FormException {

        return newInstancesFromHeteroList(req,formData.get(key),descriptors);
    }

    public static <T extends Describable<T>>
    List<T> newInstancesFromHeteroList(StaplerRequest req, Object formData,
                Collection<? extends Descriptor<T>> descriptors) throws FormException {

        List<T> items = new ArrayList<T>();

        if (formData!=null) {
            for (Object o : JSONArray.fromObject(formData)) {
                JSONObject jo = (JSONObject)o;
                String kind = jo.getString("kind");
                items.add(find(descriptors,kind).newInstance(req,jo));
            }
        }

        return items;
    }

    /**
     * Finds a descriptor from a collection by its class name.
     */
    public static <T extends Descriptor> T find(Collection<? extends T> list, String className) {
        for (T d : list) {
            if(d.getClass().getName().equals(className))
                return d;
        }
        // Since we introduced Descriptor.getId(), it is a preferred method of identifying descriptor by a string.
        // To make that migration easier without breaking compatibility, let's also match up with the id.
        for (T d : list) {
            if(d.getId().equals(className))
                return d;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -936,7 +936,10 @@
             for (Object o : JSONArray.fromObject(formData)) {
                 JSONObject jo = (JSONObject)o;
                 String kind = jo.getString("kind");
-                items.add(find(descriptors,kind).newInstance(req,jo));
+                Descriptor<T> d = find(descriptors, kind);
+                if (d != null) {
+                    items.add(d.newInstance(req, jo));
+                }
             }
         }
 
@@ -946,7 +949,7 @@
     /**
      * Finds a descriptor from a collection by its class name.
      */
-    public static <T extends Descriptor> T find(Collection<? extends T> list, String className) {
+    public static @CheckForNull <T extends Descriptor> T find(Collection<? extends T> list, String className) {
         for (T d : list) {
             if(d.getClass().getName().equals(className))
                 return d;
@@ -960,7 +963,7 @@
         return null;
     }
 
-    public static Descriptor find(String className) {
+    public static @CheckForNull Descriptor find(String className) {
         return find(Jenkins.getInstance().getExtensionList(Descriptor.class),className);
     }
 
```
