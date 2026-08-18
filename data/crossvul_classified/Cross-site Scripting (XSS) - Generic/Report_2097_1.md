# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 2097_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2097_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 749-789 of the vulnerable file.

        private final Set<User> modified = new HashSet<User>();
        private final String iconSize;
        public final ModelObject parent;

        /** @see Jenkins#getAsynchPeople} */
        public AsynchPeople(Jenkins parent) {
            this.parent = parent;
            items = parent.getItems();
            unknown = User.getUnknown();
        }

        /** @see View#getAsynchPeople */
        public AsynchPeople(View parent) {
            this.parent = parent;
            items = parent.getItems();
            unknown = null;
        }

        {
            StaplerRequest req = Stapler.getCurrentRequest();
            iconSize = req != null ? Functions.getCookie(req, "iconSize", "32x32") : "32x32";
        }

        @Override protected void compute() throws Exception {
            int itemCount = 0;
            for (Item item : items) {
                for (Job<?,?> job : item.getAllJobs()) {
                    if (job instanceof AbstractProject) {
                        AbstractProject<?,?> p = (AbstractProject) job;
                        RunList<? extends AbstractBuild<?,?>> builds = p.getBuilds();
                        int buildCount = 0;
                        for (AbstractBuild<?,?> build : builds) {
                            if (canceled()) {
                                return;
                            }
                            for (ChangeLogSet.Entry entry : build.getChangeSet()) {
                                User user = entry.getAuthor();
                                UserInfo info = users.get(user);
                                if (info == null) {
                                    UserInfo userInfo = new UserInfo(user, p, build.getTimestamp());
                                    userInfo.avatar = UserAvatarResolver.resolve(user, iconSize);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -766,7 +766,7 @@
 
         {
             StaplerRequest req = Stapler.getCurrentRequest();
-            iconSize = req != null ? Functions.getCookie(req, "iconSize", "32x32") : "32x32";
+            iconSize = req != null ? Functions.validateIconSize(Functions.getCookie(req, "iconSize", "32x32")) : "32x32";
         }
 
         @Override protected void compute() throws Exception {
```
