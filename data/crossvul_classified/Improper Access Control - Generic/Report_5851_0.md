# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 5851_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5851_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 1897-1937 of the vulnerable file.


        
        if(req.getParameter("hasSlaveAffinity")!=null) {
            assignedNode = Util.fixEmptyAndTrim(req.getParameter("_.assignedLabelString"));
        } else {
            assignedNode = null;
        }
        canRoam = assignedNode==null;

        concurrentBuild = req.getSubmittedForm().has("concurrentBuild");

        authToken = BuildAuthorizationToken.create(req);

        setScm(SCMS.parseSCM(req,this));

        for (Trigger t : triggers())
            t.stop();
        triggers = buildDescribable(req, Trigger.for_(this));
        for (Trigger t : triggers)
            t.start(this,true);
    }

    /**
     * @deprecated
     *      As of 1.261. Use {@link #buildDescribable(StaplerRequest, List)} instead.
     */
    protected final <T extends Describable<T>> List<T> buildDescribable(StaplerRequest req, List<? extends Descriptor<T>> descriptors, String prefix) throws FormException, ServletException {
        return buildDescribable(req,descriptors);
    }

    protected final <T extends Describable<T>> List<T> buildDescribable(StaplerRequest req, List<? extends Descriptor<T>> descriptors)
        throws FormException, ServletException {

        JSONObject data = req.getSubmittedForm();
        List<T> r = new Vector<T>();
        for (Descriptor<T> d : descriptors) {
            String safeName = d.getJsonSafeClassName();
            if (req.getParameter(safeName) != null) {
                T instance = d.newInstance(req, data.getJSONObject(safeName));
                r.add(instance);
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1914,6 +1914,13 @@
         triggers = buildDescribable(req, Trigger.for_(this));
         for (Trigger t : triggers)
             t.start(this,true);
+
+        for (Publisher _t : Descriptor.newInstancesFromHeteroList(req, json, "publisher", Jenkins.getInstance().getExtensionList(BuildTrigger.DescriptorImpl.class))) {
+            BuildTrigger t = (BuildTrigger) _t;
+            for (AbstractProject downstream : t.getChildProjects(this)) {
+                downstream.checkPermission(BUILD);
+            }
+        }
     }
 
     /**
```
