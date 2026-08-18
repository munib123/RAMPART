# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 5851_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5851_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 302-342 of the vulnerable file.

                childProjectsString = childProjectsString.substring(0, childProjectsString.length() - 1).trim();
            }
            return new BuildTrigger(
                childProjectsString,
                formData.optString("threshold", Result.SUCCESS.toString()));
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        public boolean showEvenIfUnstableOption(@CheckForNull Class<? extends AbstractProject<?,?>> jobType) {
            // UGLY: for promotion process, this option doesn't make sense.
            return jobType == null || !jobType.getName().contains("PromotionProcess");
        }

        /**
         * Form validation method.
         */
        public FormValidation doCheck(@AncestorInPath Item project, @QueryParameter String value ) {
            // Require CONFIGURE permission on this project
            if(!project.hasPermission(Item.CONFIGURE))      return FormValidation.ok();

            StringTokenizer tokens = new StringTokenizer(Util.fixNull(value),",");
            boolean hasProjects = false;
            while(tokens.hasMoreTokens()) {
                String projectName = tokens.nextToken().trim();
                if (StringUtils.isNotBlank(projectName)) {
                    Item item = Jenkins.getInstance().getItem(projectName,project,Item.class);
                    if(item==null)
                        return FormValidation.error(Messages.BuildTrigger_NoSuchProject(projectName,
                                AbstractProject.findNearest(projectName,project.getParent()).getRelativeNameFrom(project)));
                    if(!(item instanceof AbstractProject))
                        return FormValidation.error(Messages.BuildTrigger_NotBuildable(projectName));
                    hasProjects = true;
                }
            }
            if (!hasProjects) {
                return FormValidation.error(Messages.BuildTrigger_NoProjectSpecified());
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -319,7 +319,7 @@
         /**
          * Form validation method.
          */
-        public FormValidation doCheck(@AncestorInPath Item project, @QueryParameter String value ) {
+        public FormValidation doCheck(@AncestorInPath Item project, @QueryParameter String value, @QueryParameter boolean upstream) {
             // Require CONFIGURE permission on this project
             if(!project.hasPermission(Item.CONFIGURE))      return FormValidation.ok();
 
@@ -334,6 +334,9 @@
                                 AbstractProject.findNearest(projectName,project.getParent()).getRelativeNameFrom(project)));
                     if(!(item instanceof AbstractProject))
                         return FormValidation.error(Messages.BuildTrigger_NotBuildable(projectName));
+                    if (!upstream && !item.hasPermission(Item.BUILD)) {
+                        return FormValidation.error(Messages.BuildTrigger_you_have_no_permission_to_build_(projectName));
+                    }
                     hasProjects = true;
                 }
             }
```
